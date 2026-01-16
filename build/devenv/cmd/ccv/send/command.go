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

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	executor_operations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/mock_receiver"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
)

func Command() *cobra.Command {
	var args sendArgs
	var token string

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

			return run(args)
		},
	}

	cmd.Flags().StringVar(&args.receiverQualifier, "receiver-qualifier", evm.DefaultReceiverQualifier, "Receiver qualifier to use for the mock receiver contract")
	cmd.Flags().StringVar(&args.receiverAddress, "receiver-address", "", "Receiver address to use, if not provided, will look up the mock receiver contract address from the datastore")
	cmd.Flags().StringVar(&args.env, "env", "out", "Select environment file to use (e.g., 'staging' for env-staging.toml, defaults to 'out' for env-out.toml)")
	cmd.Flags().StringVar(&token, "token", "", "Token amounts to send in the format <amount>:<tokenAddress>, e.g., 1000000000000000000:0xTokenAddress")
	cmd.Flags().Uint64Var(&args.srcSel, "src", 0, "Source chain selector")
	cmd.Flags().Uint64Var(&args.destSel, "dest", 0, "Destination chain selector")
	cmd.Flags().Uint64Var(&args.finalitySel, "finality", 0, "Finality chain selector (optional, only for V3 messages)")

	_ = cmd.MarkFlagRequired("src")
	_ = cmd.MarkFlagRequired("dest")

	return cmd
}

type sendArgs struct {
	receiverQualifier string
	receiverAddress   string
	env               string

	tokenAmount cciptestinterfaces.TokenAmount

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
	lib, err := ccv.NewLib(l, envFile)
	if err != nil {
		return fmt.Errorf("no implementation found for source chain selector %d", args.srcSel)
	}

	chains, err := lib.ChainsMap(ctx)
	if err != nil {
		return fmt.Errorf("failed to get chain implementations: %w", err)
	}

	impl, ok := chains[args.srcSel]
	if !ok {
		return fmt.Errorf("no implementation found for source chain selector %d", args.srcSel)
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
				datastore.ContractType(mock_receiver.ContractType),
				semver.MustParse(mock_receiver.Deploy.Version()),
				args.receiverQualifier))
		if err != nil {
			return fmt.Errorf("failed to get mock receiver address: %w", err)
		}
		args.receiverAddress = mockReceiver.Address
	}

	messageFields := cciptestinterfaces.MessageFields{
		Receiver:    common.HexToAddress(args.receiverAddress).Bytes(),
		Data:        []byte{},
		TokenAmount: args.tokenAmount,
	}
	messageOptions, err := getMessageOptions(args, ds.Addresses())
	if err != nil {
		return fmt.Errorf("failed to get message options: %w", err)
	}

	result, err := impl.SendMessage(ctx, args.destSel, messageFields, messageOptions)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	ccv.Plog.Info().Msgf("Message ID: %s", hexutil.Encode(result.MessageID[:]))
	ccv.Plog.Info().Msgf("Receipt issuers: %s", result.ReceiptIssuers)
	return nil
}

func getMessageOptions(args sendArgs, addrs datastore.AddressRefStore) (cciptestinterfaces.MessageOptions, error) {
	if args.finalitySel == 0 {
		// V2 format - use the dedicated V2 function
		return cciptestinterfaces.MessageOptions{
			Version:             2,
			ExecutionGasLimit:   200_000,
			OutOfOrderExecution: true,
		}, nil
	}

	// V3 format with finality config
	committeeVerifierProxyRef, err := addrs.Get(
		datastore.NewAddressRefKey(
			args.srcSel,
			datastore.ContractType(committee_verifier.ResolverType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			evm.DefaultCommitteeVerifierQualifier))
	if err != nil {
		return cciptestinterfaces.MessageOptions{}, fmt.Errorf("failed to get committee verifier proxy address: %w", err)
	}
	executorRef, err := addrs.Get(
		datastore.NewAddressRefKey(
			args.srcSel,
			datastore.ContractType(executor_operations.ProxyType),
			semver.MustParse(executor_operations.Deploy.Version()),
			evm.DefaultExecutorQualifier))
	if err != nil {
		return cciptestinterfaces.MessageOptions{}, fmt.Errorf("failed to get executor address: %w", err)
	}
	return cciptestinterfaces.MessageOptions{
		Version:        3,
		FinalityConfig: uint16(args.finalitySel),
		Executor:       common.HexToAddress(executorRef.Address).Bytes(), // executor address
		ExecutorArgs:   nil,
		TokenArgs:      nil,
		CCVs: []protocol.CCV{
			{
				CCVAddress: common.HexToAddress(committeeVerifierProxyRef.Address).Bytes(),
				Args:       []byte{},
				ArgsLen:    0,
			},
		},
	}, nil
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
