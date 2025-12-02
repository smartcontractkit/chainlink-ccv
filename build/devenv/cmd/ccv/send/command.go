package send

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
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
	var selectorStrings []string
	var token string

	cmd := &cobra.Command{
		Use:     "send <src>,<dest>[,<finality>]",
		Aliases: []string{"s"},
		Args:    cobra.RangeArgs(1, 1),
		Short:   "Send a message",
		RunE: func(cmd *cobra.Command, positionalArgs []string) error {
			if len(positionalArgs) != 0 && len(selectorStrings) != 0 {
				return fmt.Errorf("cannot use both positional arguments and --selectors flag")
			}
			if len(positionalArgs) != 0 {
				selectorStrings = positionalArgs
			}

			var err error
			args.srcSel, args.destSel, args.finalitySel, err = parseSelectors(selectorStrings)
			if err != nil {
				return err
			}

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
	cmd.Flags().StringArrayVar(&selectorStrings, "selector", []string{}, "Selectors to use for the mock receiver contract, provide 2 or 3 selectors. Order is important: <src>,<dest>[,<finality>]")
	cmd.Flags().StringVar(&token, "token", "", "Token amounts to send in the format <amount>:<tokenAddress>, e.g., 1000000000000000000:0xTokenAddress")

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

	in, err := ccv.LoadOutput[ccv.Cfg](envFile)
	if err != nil {
		return fmt.Errorf("failed to load environment output: %w", err)
	}

	// Support both V2 (2 params) and V3 (3 params) formats
	if args.srcSel == 0 || args.destSel == 0 {
		return fmt.Errorf("expected source and destination selectors (src,dest for V2 or src,dest,finality for V3)")
	}

	chainIDs, wsURLs := make([]string, 0), make([]string, 0)
	for _, bc := range in.Blockchains {
		chainIDs = append(chainIDs, bc.ChainID)
		wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
	}

	_, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
	if err != nil {
		return fmt.Errorf("creating CLDF operations environment: %w", err)
	}
	ctx = ccv.Plog.WithContext(ctx)
	l := zerolog.Ctx(ctx)
	impl, err := evm.NewCCIP17EVM(ctx, *l, e, chainIDs, wsURLs)
	if err != nil {
		return fmt.Errorf("failed to create CCIP17EVM: %w", err)
	}

	// resolve mock receiver address if not provided
	if args.receiverAddress == "" {
		mockReceiver, err := in.CLDF.DataStore.Addresses().Get(
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
	messageOptions, err := getMessageOptions(args, in.CLDF.DataStore.Addresses())
	if err != nil {
		return fmt.Errorf("failed to get message options: %w", err)
	}

	result, err := impl.SendMessage(ctx, args.srcSel, args.destSel, messageFields, messageOptions)
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
			datastore.ContractType(committee_verifier.ResolverProxyType),
			semver.MustParse(committee_verifier.Deploy.Version()),
			evm.DefaultCommitteeVerifierQualifier))
	if err != nil {
		return cciptestinterfaces.MessageOptions{}, fmt.Errorf("failed to get committee verifier proxy address: %w", err)
	}
	executorRef, err := addrs.Get(
		datastore.NewAddressRefKey(
			args.srcSel,
			datastore.ContractType(executor_operations.ContractType),
			semver.MustParse(executor_operations.Deploy.Version()),
			""))
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

func parseSelectors(input []string) (src, dest, finality uint64, err error) {
	src, err = strconv.ParseUint(input[0], 10, 64)
	if err != nil {
		err = fmt.Errorf("failed to parse source chain selector: %w", err)
		return src, dest, finality, err
	}
	dest, err = strconv.ParseUint(input[1], 10, 64)
	if err != nil {
		err = fmt.Errorf("failed to parse destination chain selector: %w", err)
		return src, dest, finality, err
	}
	finality, err = strconv.ParseUint(input[2], 10, 64)
	if err != nil {
		err = fmt.Errorf("failed to parse finality chain selector: %w", err)
		return src, dest, finality, err
	}
	return src, dest, finality, err
}
