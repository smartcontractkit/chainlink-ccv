package fetch_signing_keys

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// SigningKeysByNOP maps NOP alias -> chain family -> signer address.
type SigningKeysByNOP map[string]map[string]string

type FetchSigningKeysInput struct {
	NOPAliases []string
}

type FetchSigningKeysOutput struct {
	SigningKeysByNOP SigningKeysByNOP
	// RawPubKeyByNOP maps NOP alias -> raw uncompressed secp256k1 public key (hex, no
	// 0x prefix, lowercased). A standalone node registers one signing key across every
	// chain it declares, so this lets callers derive a signer address for a family the
	// NOP never declared directly (e.g. a Canton verifier's EVM address), rather than
	// only translating between families it already has an OnchainSigningAddress for.
	RawPubKeyByNOP map[string]string
}

type FetchSigningKeysDeps struct {
	JDClient shared.JDClient
	Logger   logger.Logger
	NodeIDs  []string
}

var FetchNOPSigningKeys = operations.NewOperation(
	"fetch-nop-signing-keys",
	semver.MustParse("1.0.0"),
	"Fetches signing keys for all specified NOPs from the job distributor in a single batch",
	func(b operations.Bundle, deps FetchSigningKeysDeps, input FetchSigningKeysInput) (FetchSigningKeysOutput, error) {
		ctx := b.GetContext()
		lggr := deps.Logger

		output := FetchSigningKeysOutput{
			SigningKeysByNOP: make(SigningKeysByNOP),
			RawPubKeyByNOP:   make(map[string]string),
		}

		if len(input.NOPAliases) == 0 {
			return output, nil
		}

		lookup, err := shared.FetchNodeLookup(ctx, deps.JDClient, deps.NodeIDs)
		if err != nil {
			return output, err
		}

		nodeIDs := make([]string, 0, len(input.NOPAliases))
		nodeIDToAlias := make(map[string]string)
		seenNodeIDs := make(map[string]string)
		for _, nopAlias := range input.NOPAliases {
			node, ok := lookup.FindByName(nopAlias)
			if !ok {
				return output, fmt.Errorf("NOP alias %q not found in node lookup (node IDs: %v)", nopAlias, deps.NodeIDs)
			}
			if existing, ok := seenNodeIDs[node.Id]; ok && existing != nopAlias {
				return output, fmt.Errorf("duplicate node ID %q: NOP aliases %q and %q both resolve to the same node", node.Id, existing, nopAlias)
			}
			seenNodeIDs[node.Id] = nopAlias
			nodeIDs = append(nodeIDs, node.Id)
			nodeIDToAlias[node.Id] = nopAlias
		}

		chainConfigsResp, err := deps.JDClient.ListNodeChainConfigs(ctx, &nodev1.ListNodeChainConfigsRequest{
			Filter: &nodev1.ListNodeChainConfigsRequest_Filter{
				NodeIds: nodeIDs,
			},
		})
		if err != nil {
			return output, fmt.Errorf("failed to list chain configs: %w", err)
		}

		for _, chainConfig := range chainConfigsResp.ChainConfigs {
			if chainConfig.Ocr2Config == nil || chainConfig.Ocr2Config.OcrKeyBundle == nil {
				continue
			}

			nopAlias, ok := nodeIDToAlias[chainConfig.NodeId]
			if !ok {
				continue
			}

			bundle := chainConfig.Ocr2Config.OcrKeyBundle
			if strings.TrimSpace(bundle.OnchainSigningAddress) == "" {
				continue
			}

			chainFamily, ok := shared.GetChainTypeFamily(chainConfig.Chain.Type)
			if !ok {
				lggr.Debugw("Skipping unsupported chain type",
					"chainType", chainConfig.Chain.Type.String())
				continue
			}

			if output.SigningKeysByNOP[nopAlias] == nil {
				output.SigningKeysByNOP[nopAlias] = make(map[string]string)
			}

			setKey := func(family, identity string) error {
				addr := shared.NormalizeAddress(family, identity)
				if existing, ok := output.SigningKeysByNOP[nopAlias][family]; ok && existing != addr {
					return fmt.Errorf(
						"NOP %q has conflicting OCR key bundles for family %s: address %s vs %s — the job spec requires a single signing address (per-chain scoping not supported yet)",
						nopAlias, family, existing, addr,
					)
				}
				output.SigningKeysByNOP[nopAlias][family] = addr
				return nil
			}

			native, err := shared.SigningIdentityFromBundle(chainFamily, bundle)
			if err != nil {
				continue
			}
			if err := setKey(chainFamily, native); err != nil {
				return output, err
			}

			if chainFamily != chainsel.FamilyEVM {
				evmIdentity, err := shared.SigningIdentityFromBundle(chainsel.FamilyEVM, bundle)
				if err == nil {
					if err := setKey(chainsel.FamilyEVM, evmIdentity); err != nil {
						return output, err
					}
				}
			}

			// Capture the raw public key too, so callers can bridge this NOP's identity
			// into a family it never declared directly (see RawPubKeyByNOP).
			if rawPubKey := chainConfig.Ocr2Config.OcrKeyBundle.OnchainSigningPubKey; rawPubKey != "" {
				normalized := strings.ToLower(strings.TrimPrefix(rawPubKey, "0x"))
				if existing, ok := output.RawPubKeyByNOP[nopAlias]; ok && existing != normalized {
					return output, fmt.Errorf("NOP %q has conflicting raw public keys across chain configs: %s vs %s — a standalone node registers one key for every chain it declares", nopAlias, existing, normalized)
				}
				output.RawPubKeyByNOP[nopAlias] = normalized
			}

			lggr.Debugw("Found signing address",
				"nopAlias", nopAlias,
				"nodeId", chainConfig.NodeId,
				"chainFamily", chainFamily,
				"signerAddress", native)
		}

		return output, nil
	},
)
