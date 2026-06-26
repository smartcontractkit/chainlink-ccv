package changesets

import (
	"context"
	"fmt"
	"maps"
	"sort"

	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/operations/fetch_signing_keys"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// NOPIdentities carries the JD-sourced mapping between NOP aliases and their
// onchain signer addresses, in both directions.
//
// It is the offchain half of state-based input resolution: on-chain scans (e.g.
// CommitteeVerifierOnchainAdapter.ScanCommitteeStates) only ever see signer
// addresses, never NOP aliases. NOPIdentities is what turns those addresses back
// into the aliases the changeset inputs are expressed in. Build it once per
// resolve via LoadNOPIdentities and thread it through every committee/pool
// reconstruction.
type NOPIdentities struct {
	// signingKeys is alias -> chain family -> signer address (the JD source of
	// truth, already normalized via shared.NormalizeAddress by the fetch op).
	signingKeys fetch_signing_keys.SigningKeysByNOP
	// aliasBySigner is the inverse: family -> normalized signer address -> alias.
	aliasBySigner map[string]map[string]shared.NOPAlias
}

// LoadNOPIdentities builds the alias↔signer maps from two complementary sources:
//
//   - the Job Distributor (env.Offchain): OCR on-chain signing addresses for the
//     CL-mode NOPs JD manages — fetched when a JD client and node IDs are present.
//   - the persisted signer index (env.DataStore): the alias→signer mapping written
//     by ApplyVerifierConfig, which covers NOPs JD does not manage — notably
//     standalone verifiers, whose signing address never reaches JD.
//
// JD (live) takes precedence on overlap; the persisted index fills in the rest.
// Neither source is mandatory — with both empty the identity set is empty, and any
// unmappable on-chain signer surfaces later as an explicit error.
func LoadNOPIdentities(ctx context.Context, env deployment.Environment) (*NOPIdentities, error) {
	signers := make(fetch_signing_keys.SigningKeysByNOP)

	// CL-mode NOPs from JD.
	if env.Offchain != nil && len(env.NodeIDs) > 0 {
		aliases, err := listNOPAliases(ctx, env)
		if err != nil {
			return nil, err
		}
		report, err := operations.ExecuteOperation(
			env.OperationsBundle,
			fetch_signing_keys.FetchNOPSigningKeys,
			fetch_signing_keys.FetchSigningKeysDeps{
				JDClient: env.Offchain,
				Logger:   env.Logger,
				NodeIDs:  env.NodeIDs,
			},
			fetch_signing_keys.FetchSigningKeysInput{NOPAliases: aliases},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch NOP signing keys from JD: %w", err)
		}
		for alias, byFamily := range report.Output.SigningKeysByNOP {
			signers[alias] = maps.Clone(byFamily)
		}
	}

	// Standalone (and any other non-JD) NOPs from the persisted index. JD wins on
	// overlap, so only fill (alias, family) pairs JD didn't provide.
	if env.DataStore != nil {
		index, err := ccvdeployment.GetNOPSigners(env.DataStore)
		if err != nil {
			return nil, fmt.Errorf("failed to read persisted NOP signer index: %w", err)
		}
		for alias, byFamily := range index {
			if signers[alias] == nil {
				signers[alias] = make(map[string]string, len(byFamily))
			}
			for family, addr := range byFamily {
				if _, ok := signers[alias][family]; !ok {
					signers[alias][family] = addr
				}
			}
		}
	}

	return newNOPIdentities(signers), nil
}

// newNOPIdentities builds the inverse index from a forward signing-keys map.
// Exposed (unexported) so tests can construct identities without a JD round-trip.
func newNOPIdentities(signingKeys fetch_signing_keys.SigningKeysByNOP) *NOPIdentities {
	inv := make(map[string]map[string]shared.NOPAlias)
	for alias, byFamily := range signingKeys {
		for family, signer := range byFamily {
			if signer == "" {
				continue
			}
			if inv[family] == nil {
				inv[family] = make(map[string]shared.NOPAlias)
			}
			inv[family][shared.NormalizeAddress(family, signer)] = shared.NOPAlias(alias)
		}
	}
	return &NOPIdentities{signingKeys: signingKeys, aliasBySigner: inv}
}

// AliasForSigner resolves an on-chain signer address (for the given chain family)
// back to its NOP alias. ok=false means an on-chain signer with no JD-known owner
// — callers should surface that as drift rather than silently dropping it.
func (ids *NOPIdentities) AliasForSigner(family, signer string) (shared.NOPAlias, bool) {
	byAddr, ok := ids.aliasBySigner[family]
	if !ok {
		return "", false
	}
	alias, ok := byAddr[shared.NormalizeAddress(family, signer)]
	return alias, ok
}

// NOPInputs returns one NOPInput per JD-known NOP, populated with the signer
// addresses observed in JD. It is the state analog of NOPInputsFromTopology.
//
// Mode is intent, not observable state — it defaults to CL here; callers that
// run standalone NOPs should override via the resolver options.
func (ids *NOPIdentities) NOPInputs() []NOPInput {
	out := make([]NOPInput, 0, len(ids.signingKeys))
	for alias, byFamily := range ids.signingKeys {
		signers := make(map[string]string, len(byFamily))
		maps.Copy(signers, byFamily)
		out = append(out, NOPInput{
			Alias:                 shared.NOPAlias(alias),
			SignerAddressByFamily: signers,
			Mode:                  shared.NOPModeCL,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// listNOPAliases returns the node names (NOP aliases) registered with JD for the
// environment's NodeIDs. Node name is the canonical NOP alias across the
// deployment layer (see shared.NodeLookup).
func listNOPAliases(ctx context.Context, env deployment.Environment) ([]string, error) {
	resp, err := env.Offchain.ListNodes(ctx, &nodev1.ListNodesRequest{
		Filter: &nodev1.ListNodesRequest_Filter{Ids: env.NodeIDs},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes from JD: %w", err)
	}
	aliases := make([]string, 0, len(resp.Nodes))
	for _, node := range resp.Nodes {
		if node.Name != "" {
			aliases = append(aliases, node.Name)
		}
	}
	if len(aliases) == 0 {
		return nil, fmt.Errorf("no named nodes returned by JD for node IDs %v", env.NodeIDs)
	}
	return aliases, nil
}
