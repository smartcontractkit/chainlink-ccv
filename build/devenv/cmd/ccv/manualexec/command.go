package manualexec

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	v1 "github.com/smartcontractkit/chainlink-ccv/indexer/pkg/api/handlers/v1"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

func Command() *cobra.Command {
	type args struct {
		chainSelector     uint64
		messageID         string
		env               string
		indexerResultJSON string
		gasLimit          uint64
	}
	var a args

	manuallyExecuteCmd := &cobra.Command{
		Use:   "manually-execute",
		Short: "Manually execute a message",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			l := zerolog.Ctx(ctx)
			envFile := fmt.Sprintf("env-%s.toml", a.env)
			impl, err := ccv.NewImpl(l, envFile, a.chainSelector)
			if err != nil {
				return fmt.Errorf("no implementation found for source chain selector %d", a.chainSelector)
			}

			var messageIDBytes32 protocol.Bytes32
			messageIDBytes := hexutil.MustDecode(a.messageID)
			copy(messageIDBytes32[:], messageIDBytes)

			var resp v1.MessageIDResponse
			err = json.Unmarshal([]byte(a.indexerResultJSON), &resp)
			if err != nil {
				return fmt.Errorf("failed to unmarshal indexer result JSON: %w", err)
			}

			msg := resp.Results[0].VerifierResult.Message
			ccvs := make([]protocol.UnknownAddress, 0, len(resp.Results))
			verifierResults := make([][]byte, 0, len(resp.Results))
			for _, result := range resp.Results {
				ccvs = append(ccvs, result.VerifierResult.VerifierDestAddress)
				verifierResults = append(verifierResults, result.VerifierResult.CCVData)
			}

			_, err = impl.ManuallyExecuteMessage(cmd.Context(), msg, a.gasLimit, ccvs, verifierResults)
			if err != nil {
				return fmt.Errorf("failed to manually execute message: %w", err)
			}

			return nil
		},
	}

	manuallyExecuteCmd.Flags().Uint64Var(&a.chainSelector, "chain-selector", 0, "Chain selector to manually execute message for")
	manuallyExecuteCmd.Flags().StringVar(&a.messageID, "message-id", "", "Message ID of the messageto manually execute")
	manuallyExecuteCmd.Flags().StringVar(&a.env, "env", "out", "Select environment file to use (e.g., 'staging' for env-staging.toml, defaults to env-out.toml)")
	manuallyExecuteCmd.Flags().StringVar(&a.indexerResultJSON, "indexer-result-json", "", "Indexer result JSON to manually execute message from")
	manuallyExecuteCmd.Flags().Uint64Var(&a.gasLimit, "gas-limit", 0, "Gas limit to use for the manually executed message")

	_ = manuallyExecuteCmd.MarkFlagRequired("chain-selector")
	_ = manuallyExecuteCmd.MarkFlagRequired("message-id")
	_ = manuallyExecuteCmd.MarkFlagRequired("indexer-result-json")
	_ = manuallyExecuteCmd.MarkFlagRequired("gas-limit")

	return manuallyExecuteCmd
}
