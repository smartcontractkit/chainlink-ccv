package manualexec

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	chainsel "github.com/smartcontractkit/chain-selectors"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/evm"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
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
			envFile := fmt.Sprintf("env-%s.toml", a.env)
			in, err := ccv.LoadOutput[ccv.Cfg](envFile)
			if err != nil {
				return fmt.Errorf("failed to load environment output: %w", err)
			}

			var messageIDBytes32 protocol.Bytes32
			messageIDBytes := hexutil.MustDecode(a.messageID)
			copy(messageIDBytes32[:], messageIDBytes)

			var resp protocol.MessageIDV1Response
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

			chainID, err := chainsel.ChainIdFromSelector(a.chainSelector)
			if err != nil {
				return fmt.Errorf("failed to get chain details: %w", err)
			}
			chainIDStr := strconv.FormatUint(chainID, 10)

			// get the blockchain input for the chain selector
			var input *blockchain.Input
			for _, bc := range in.Blockchains {
				if bc.ChainID == chainIDStr {
					input = bc
					break
				}
			}
			if input == nil {
				return fmt.Errorf("blockchain with chain ID %s not found, please update the env file or use a different chain-selector", chainIDStr)
			}

			// TODO: this kind of thing should be chain-agnostic.
			chainIDs, wsURLs := make([]string, 0), make([]string, 0)
			for _, bc := range in.Blockchains {
				chainIDs = append(chainIDs, bc.ChainID)
				wsURLs = append(wsURLs, bc.Out.Nodes[0].ExternalWSUrl)
			}
			_, e, err := ccv.NewCLDFOperationsEnvironment(in.Blockchains, in.CLDF.DataStore)
			if err != nil {
				return fmt.Errorf("failed to create CLDF operations environment: %w", err)
			}
			l := log.
				Output(zerolog.ConsoleWriter{Out: os.Stderr}).
				Level(zerolog.DebugLevel).
				With().
				Fields(map[string]any{"component": "CCIP17EVM"}).
				Logger()
			impl, err := evm.NewCCIP17EVM(cmd.Context(), l, e, chainIDs, wsURLs)
			if err != nil {
				return fmt.Errorf("failed to create CCIP17EVM: %w", err)
			}
			// END TODO.

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
