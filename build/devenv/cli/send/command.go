package send

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/link"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_0_0/operations/weth"
	executor_operations "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/operations/mock_receiver_v2"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/sequences"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v2_0_0/versioned_verifier_resolver"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/evm"
)

func Command() *cobra.Command {
	var args sendArgs
	var token string
	var feeToken string

	cmd := &cobra.Command{
		Use:     "send",
		Aliases: []string{"s"},
		Short:   "Send a message",
		RunE: func(cmd *cobra.Command, positionalArgs []string) error {
			var err error
			args.tokenAmount, err = parseTokenAmount(token)
			if err != nil {
				return err
			}
			args.feeToken = feeToken

			return run(args)
		},
	}

	cmd.Flags().StringVar(&args.receiverQualifier, "receiver-qualifier", devenvcommon.DefaultReceiverQualifier, "Receiver qualifier to use for the mock receiver contract")
	cmd.Flags().StringVar(&args.receiverAddress, "receiver-address", "", "Receiver address to use, if not provided, will look up the mock receiver contract address from the datastore")
	cmd.Flags().StringVar(&args.env, "env", "out", "Select environment file to use (e.g., 'staging' for env-staging.toml, defaults to 'out' for env-out.toml)")
	cmd.Flags().StringVar(&token, "token", "", "Token amounts to send in the format <amount>:<tokenAddress>, e.g., 1000000000000000000:0xTokenAddress")
	cmd.Flags().StringVar(&feeToken, "fee-token", "", "Fee token to pay in: empty/'native' (default), 'wrapped'/'weth' for wrapped native, 'link' for LINK, or a raw 0x... address on the source chain")
	cmd.Flags().Uint64Var(&args.srcSel, "src", 0, "Source chain selector")
	cmd.Flags().Uint64Var(&args.destSel, "dest", 0, "Destination chain selector")
	cmd.Flags().Uint64Var(&args.finalitySel, "finality", 0, "Finality chain selector (optional, only for V3 messages)")
	cmd.Flags().BoolVar(&args.omitCommittee, "omit-committee", false, "Omit committee verifier from CCVs (e.g. for CCTP-only sends)")
	cmd.Flags().BoolVar(&args.useTestRouter, "use-test-router", false, "Look up TestRouter contract from datastore instead of regular Router")

	_ = cmd.MarkFlagRequired("src")
	_ = cmd.MarkFlagRequired("dest")

	return cmd
}

type sendArgs struct {
	receiverQualifier string
	receiverAddress   string
	env               string
	useTestRouter     bool
	omitCommittee     bool

	tokenAmount cciptestinterfaces.TokenAmount
	feeToken    string

	srcSel      uint64
	destSel     uint64
	finalitySel uint64
}

func run(args sendArgs) error {
	ctx := context.Background()
	ctx = ccv.Plog.WithContext(ctx)
	envFile := fmt.Sprintf("env-%s.toml", args.env)

	// Support both V2 (2 params) and V3 (3 params) formats
	if args.srcSel == 0 || args.destSel == 0 {
		return fmt.Errorf("expected source and destination selectors (src,dest for V2 or src,dest,finality for V3)")
	}

	l := zerolog.Ctx(ctx)
	lib, err := ccv.NewLib(l, envFile, chain_selectors.FamilyEVM)
	if err != nil {
		return fmt.Errorf("failed to initialize lib from %s: %w", envFile, err)
	}

	chains, err := lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain implementations: %w", err)
	}

	impl, ok := chains[args.srcSel]
	if !ok {
		available := make([]uint64, 0, len(chains))
		for sel := range chains {
			available = append(available, sel)
		}
		return fmt.Errorf("no implementation found for source chain selector %d (available: %v)", args.srcSel, available)
	}

	ds, err := lib.DataStore()
	if err != nil {
		return fmt.Errorf("failed to get datastore: %w", err)
	}

	// resolve mock receiver address if not provided
	if args.receiverAddress == "" {
		mockReceiver, err := ds.Addresses().Get(
			datastore.NewAddressRefKey(
				args.destSel,
				datastore.ContractType(mock_receiver_v2.ContractType),
				semver.MustParse(mock_receiver_v2.Deploy.Version()),
				args.receiverQualifier))
		if err != nil {
			return fmt.Errorf("failed to get mock receiver address: %w", err)
		}
		args.receiverAddress = mockReceiver.Address
	}

	feeTokenAddr, err := resolveFeeToken(args.feeToken, args.srcSel, ds.Addresses())
	if err != nil {
		return fmt.Errorf("failed to resolve fee token: %w", err)
	}

	messageFields := cciptestinterfaces.MessageFields{
		Receiver:    common.HexToAddress(args.receiverAddress).Bytes(),
		Data:        []byte{},
		TokenAmount: args.tokenAmount,
		FeeToken:    feeTokenAddr,
	}
	messageOptions, msgVersion, err := getMessageOptions(args, ds.Addresses())
	if err != nil {
		return fmt.Errorf("failed to get message options: %w", err)
	}

	senderImpl, ok := impl.(cciptestinterfaces.ChainAsSource)
	if !ok {
		return fmt.Errorf("impl is not ChainAsSource")
	}

	// use evm impl for now, until we have a long term plan for the cli.
	extraArgs, err := evm.SerializeEVMExtraArgs(msgVersion, messageOptions)
	if err != nil {
		return fmt.Errorf("failed to serialize extra args: %w", err)
	}

	message, err := senderImpl.BuildChainMessage(ctx, messageFields, extraArgs)
	if err != nil {
		return fmt.Errorf("failed to build message: %w", err)
	}
	result, _, err := senderImpl.SendChainMessage(ctx, args.destSel, message, evm.SendOptions{
		UseTestRouter: args.useTestRouter,
	})
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	ccv.Plog.Info().Msgf("Message ID: %s", hexutil.Encode(result.MessageID[:]))
	ccv.Plog.Info().Msgf("Receipt issuers: %s", result.ReceiptIssuers)
	return nil
}

func getMessageOptions(args sendArgs, addrs datastore.AddressRefStore) (cciptestinterfaces.MessageOptions, uint8, error) {
	if args.finalitySel == 0 {
		// V2 format - use the dedicated V2 function
		return cciptestinterfaces.MessageOptions{
			ExecutionGasLimit:   200_000,
			OutOfOrderExecution: true,
		}, 2, nil
	}

	// V3 format with finality config
	executorRef, err := addrs.Get(
		datastore.NewAddressRefKey(
			args.srcSel,
			datastore.ContractType(sequences.ExecutorProxyType),
			semver.MustParse(executor_operations.Deploy.Version()),
			devenvcommon.DefaultExecutorQualifier))
	if err != nil {
		return cciptestinterfaces.MessageOptions{}, 0, fmt.Errorf("failed to get executor address: %w", err)
	}
	opts := cciptestinterfaces.MessageOptions{
		FinalityConfig: protocol.Finality(args.finalitySel),
		Executor:       common.HexToAddress(executorRef.Address).Bytes(),
		ExecutorArgs:   nil,
		TokenArgs:      nil,
	}
	if args.omitCommittee {
		opts.CCVs = nil
		return opts, 3, nil
	}
	committeeVerifierProxyRef, err := addrs.Get(
		datastore.NewAddressRefKey(
			args.srcSel,
			datastore.ContractType(versioned_verifier_resolver.CommitteeVerifierResolverType),
			versioned_verifier_resolver.Version,
			devenvcommon.DefaultCommitteeVerifierQualifier))
	if err != nil {
		return cciptestinterfaces.MessageOptions{}, 0, fmt.Errorf("failed to get committee verifier proxy address: %w", err)
	}
	opts.CCVs = []protocol.CCV{
		{
			CCVAddress: common.HexToAddress(committeeVerifierProxyRef.Address).Bytes(),
			Args:       []byte{},
			ArgsLen:    0,
		},
	}
	return opts, 3, nil
}

// resolveFeeToken converts the --fee-token CLI value into an on-chain address.
// Supported inputs:
//   - "" or "native": pay in the chain's native gas token (zero address).
//   - "wrapped" / "weth" / "wrapped-native": look up the wrapped native (WETH) on
//     the source chain from the datastore.
//   - "link": look up the LINK token on the source chain from the datastore.
//   - a raw 0x... hex address: used as-is.
func resolveFeeToken(input string, srcSel uint64, addrs datastore.AddressRefStore) (protocol.UnknownAddress, error) {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "", "native":
		return nil, nil
	case "wrapped", "weth", "wrapped-native":
		ref, err := addrs.Get(datastore.NewAddressRefKey(
			srcSel,
			datastore.ContractType(weth.ContractType),
			semver.MustParse(weth.Deploy.Version()),
			""))
		if err != nil {
			return nil, fmt.Errorf("failed to look up wrapped native (WETH) on source chain %d: %w", srcSel, err)
		}
		return protocol.UnknownAddress(common.HexToAddress(ref.Address).Bytes()), nil
	case "link":
		ref, err := addrs.Get(datastore.NewAddressRefKey(
			srcSel,
			datastore.ContractType(link.ContractType),
			link.Version,
			""))
		if err != nil {
			return nil, fmt.Errorf("failed to look up LINK on source chain %d: %w", srcSel, err)
		}
		return protocol.UnknownAddress(common.HexToAddress(ref.Address).Bytes()), nil
	default:
		if !common.IsHexAddress(input) {
			return nil, fmt.Errorf("invalid fee token %q: expected 'native', 'wrapped'/'weth', 'link', or a 0x... address", input)
		}
		return protocol.UnknownAddress(common.HexToAddress(input).Bytes()), nil
	}
}

func parseTokenAmount(input string) (cciptestinterfaces.TokenAmount, error) {
	if input == "" {
		return cciptestinterfaces.TokenAmount{}, nil
	}

	parts := strings.Split(input, ":")
	if len(parts) != 2 {
		return cciptestinterfaces.TokenAmount{}, fmt.Errorf("invalid token amount format: %s, expected <amount>:<address>", input)
	}
	amount, ok := new(big.Int).SetString(parts[0], 10)
	if !ok {
		return cciptestinterfaces.TokenAmount{}, fmt.Errorf("invalid token amount: %s", parts[0])
	}
	if !common.IsHexAddress(parts[1]) {
		return cciptestinterfaces.TokenAmount{}, fmt.Errorf("invalid token address: %s", parts[1])
	}

	tokenAddress := common.HexToAddress(parts[1])
	return cciptestinterfaces.TokenAmount{
		Amount:       amount,
		TokenAddress: tokenAddress.Bytes(),
	}, nil
}
