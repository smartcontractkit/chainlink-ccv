package send

import (
	"context"
	"fmt"
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

	cmd := &cobra.Command{
		Use:     "send <src>,<dest>[,<finality>]",
		Aliases: []string{"s"},
		Args:    cobra.RangeArgs(1, 1),
		Short:   "Send a message",
		RunE: func(cmd *cobra.Command, positionalArgs []string) error {
			args.selectors = strings.Split(positionalArgs[0], ",")
			return run(args)
		},
	}

	cmd.Flags().StringVar(&args.receiverQualifier, "receiver-qualifier", evm.DefaultReceiverQualifier, "Receiver qualifier to use for the mock receiver contract")
	cmd.Flags().StringVar(&args.env, "env", "out", "Select environment file to use (e.g., 'staging' for env-staging.toml, defaults to 'out' for env-out.toml)")

	return cmd
}

type sendArgs struct {
	receiverQualifier string
	env               string
	selectors         []string
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
	if len(args.selectors) != 2 && len(args.selectors) != 3 {
		return fmt.Errorf("expected 2 or 3 parameters (src,dest for V2 or src,dest,finality for V3), got %d", len(args.selectors))
	}

	src, err := strconv.ParseUint(args.selectors[0], 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse source chain selector: %w", err)
	}
	dest, err := strconv.ParseUint(args.selectors[1], 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse destination chain selector: %w", err)
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

	mockReceiverRef, err := in.CLDF.DataStore.Addresses().Get(
		datastore.NewAddressRefKey(
			dest,
			datastore.ContractType(mock_receiver.ContractType),
			semver.MustParse(mock_receiver.Deploy.Version()),
			args.receiverQualifier))
	if err != nil {
		return fmt.Errorf("failed to get mock receiver address: %w", err)
	}
	// Use V3 if finality config is provided, otherwise use V2
	var result cciptestinterfaces.MessageSentEvent
	if len(args.selectors) == 3 {
		// V3 format with finality config
		finality, err := strconv.ParseUint(args.selectors[2], 10, 32)
		if err != nil {
			return fmt.Errorf("failed to parse finality config: %w", err)
		}

		committeeVerifierProxyRef, err := in.CLDF.DataStore.Addresses().Get(
			datastore.NewAddressRefKey(
				src,
				datastore.ContractType(committee_verifier.ResolverProxyType),
				semver.MustParse(committee_verifier.Deploy.Version()),
				evm.DefaultCommitteeVerifierQualifier))
		if err != nil {
			return fmt.Errorf("failed to get committee verifier proxy address: %w", err)
		}
		executorRef, err := in.CLDF.DataStore.Addresses().Get(
			datastore.NewAddressRefKey(
				src,
				datastore.ContractType(executor_operations.ContractType),
				semver.MustParse(executor_operations.Deploy.Version()),
				""))
		if err != nil {
			return fmt.Errorf("failed to get executor address: %w", err)
		}
		result, err = impl.SendMessage(ctx, src, dest, cciptestinterfaces.MessageFields{
			Receiver: protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()), // mock receiver
			Data:     []byte{},
		}, cciptestinterfaces.MessageOptions{
			Version:        3,
			FinalityConfig: uint16(finality),
			Executor:       protocol.UnknownAddress(common.HexToAddress(executorRef.Address).Bytes()), // executor address
			ExecutorArgs:   nil,
			TokenArgs:      nil,
			CCVs: []protocol.CCV{
				{
					CCVAddress: common.HexToAddress(committeeVerifierProxyRef.Address).Bytes(),
					Args:       []byte{},
					ArgsLen:    0,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to send message: %w", err)
		}
	} else {
		// V2 format - use the dedicated V2 function
		result, err = impl.SendMessage(ctx, src, dest, cciptestinterfaces.MessageFields{
			Receiver: protocol.UnknownAddress(common.HexToAddress(mockReceiverRef.Address).Bytes()), // mock receiver
			Data:     []byte{},
		}, cciptestinterfaces.MessageOptions{
			Version:             2,
			ExecutionGasLimit:   200_000,
			OutOfOrderExecution: true,
		})
		if err != nil {
			return fmt.Errorf("failed to send message: %w", err)
		}
	}
	ccv.Plog.Info().Msgf("Message ID: %s", hexutil.Encode(result.MessageID[:]))
	ccv.Plog.Info().Msgf("Receipt issuers: %s", result.ReceiptIssuers)
	return nil
}
