package tokenverifier

import (
	"context"
	"fmt"
	"strconv"

	chainsel "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	blockchainscomp "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/blockchains"
	fakecomp "github.com/smartcontractkit/chainlink-ccv/build/devenv/components/fake"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const Key = "token_verifier"

// Version is the token_verifier component config schema version. Exactly this
// version is supported; configs declaring any other version are rejected.
const Version = 1

func init() {
	if err := devenvruntime.Register(Key, factory); err != nil {
		panic(fmt.Sprintf("tokenverifier component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(componentConfig any) error {
	_, err := decode(componentConfig)
	return err
}

// RunPhase4 decodes [[token_verifier]] config, generates token verifier
// configuration from on-chain state via changeset, and launches standalone
// containers. It publishes the populated inputs under "token_verifier" so
// NewPhasedEnvironment can replace cfg.TokenVerifier before Store().
func (c *component) RunPhase4(
	_ context.Context,
	_ map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	inputs, err := decode(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	if len(inputs) == 0 {
		return map[string]any{}, nil, nil
	}

	e, ok := priorOutputs["_env"].(*deployment.Environment)
	if !ok || e == nil {
		return nil, nil, fmt.Errorf("tokenverifier: _env not found in phase outputs")
	}
	selectors, ok := priorOutputs["_selectors"].([]uint64)
	if !ok {
		return nil, nil, fmt.Errorf("tokenverifier: _selectors not found in phase outputs")
	}
	blockchains, ok := priorOutputs[blockchainscomp.Key].([]*blockchain.Input)
	if !ok {
		return nil, nil, fmt.Errorf("tokenverifier: blockchains not found in phase outputs")
	}
	blockchainOutputs := blockchainscomp.Outputs(blockchains)
	topology, ok := priorOutputs["environment_topology"].(*ccvdeployment.EnvironmentTopology)
	if !ok || topology == nil {
		return nil, nil, fmt.Errorf("tokenverifier: environment_topology not found in phase outputs")
	}
	fmt.Printf("tokenverifier: environment_topology: %+v\n", topology)

	var fakeOut *services.FakeOutput
	if fake, ok := priorOutputs[fakecomp.Key].(*services.FakeInput); ok && fake != nil {
		fakeOut = fake.Out
	}
	if fakeOut == nil {
		return nil, nil, fmt.Errorf("tokenverifier: fake data provider is required to provide attestation API endpoints")
	}

	familyLombardQualifier := make(map[string]string, len(inputs))
	familyCCTPQualifier := make(map[string]string, len(inputs))
	for _, in := range inputs {
		if in == nil {
			continue
		}
		fam := in.ChainFamily
		if fam == "" {
			fam = chainsel.FamilyEVM
		}
		q := in.LombardQualifier
		if q == "" {
			q = devenvcommon.LombardVerifierResolverQualifier
		}
		familyLombardQualifier[fam] = q

		q = in.CCTPQualifier
		if q == "" {
			q = devenvcommon.CCTPVerifierResolverQualifier
		}
		familyCCTPQualifier[fam] = q
	}

	localEnv := *e
	for i, tvIn := range inputs {
		if tvIn == nil {
			continue
		}

		// Each instance gets its own service identifier and is scoped to its own chain family's selectors.
		// Sharing one identifier across chain families would merge e.g. an EVM-only CCTPVerifier entry into
		// a Solana instance's config, which then fails to start (no CCTP support, no valid chain sources for it).
		family := tvIn.ChainFamily
		if family == "" {
			family = chainsel.FamilyEVM
		}
		familySelectors := selectorsForFamily(selectors, family)
		if len(familySelectors) == 0 {
			return nil, nil, fmt.Errorf("tokenverifier: no chain selectors found for family %q (instance %q)", family, tvIn.ContainerName)
		}

		lombardQualifier := familyLombardQualifier[family]
		cctpQualifier := familyCCTPQualifier[family]

		cs := ccvchangesets.GenerateTokenVerifierConfig()
		output, csErr := cs.Apply(localEnv, ccvchangesets.GenerateTokenVerifierConfigInput{
			ServiceIdentifier: tvIn.ContainerName,
			ChainSelectors:    familySelectors,
			Lombard: ccvchangesets.LombardConfigInput{
				VerifierID:     "LombardVerifier",
				Qualifier:      lombardQualifier,
				AttestationAPI: fakeOut.InternalHTTPURL + "/lombard",
			},
			CCTP: ccvchangesets.CCTPConfigInput{
				VerifierID:     "CCTPVerifier",
				Qualifier:      cctpQualifier,
				AttestationAPI: fakeOut.InternalHTTPURL + "/cctp",
			},
		})
		if csErr != nil {
			return nil, nil, fmt.Errorf("tokenverifier: generating token verifier config: %w", csErr)
		}
		localEnv.DataStore = output.DataStore.Seal()

		// A message's dest chain may belong to a different family than this instance's own
		// CCVWriter needs the Lombard verifier resolver address for the dest chain too
		// in order to annotate written CCV data with it.
		remoteByFamily := make(map[string][]uint64)
		for _, sel := range selectors {
			selFamily, err := chainsel.GetSelectorFamily(sel)
			if err != nil || selFamily == family {
				continue
			}
			remoteByFamily[selFamily] = append(remoteByFamily[selFamily], sel)
		}
		for remoteFamily, remoteSelectors := range remoteByFamily {
			remoteOutput, remoteErr := ccvchangesets.GenerateTokenVerifierConfig().Apply(localEnv, ccvchangesets.GenerateTokenVerifierConfigInput{
				ServiceIdentifier: tvIn.ContainerName,
				ChainSelectors:    remoteSelectors,
				Lombard: ccvchangesets.LombardConfigInput{
					VerifierID:     "LombardVerifier",
					Qualifier:      familyLombardQualifier[remoteFamily],
					AttestationAPI: fakeOut.InternalHTTPURL + "/lombard",
				},
				CCTP: ccvchangesets.CCTPConfigInput{
					VerifierID:     "CCTPVerifier",
					Qualifier:      familyCCTPQualifier[remoteFamily],
					AttestationAPI: fakeOut.InternalHTTPURL + "/cctp",
				},
			})
			if remoteErr != nil {
				return nil, nil, fmt.Errorf("tokenverifier: generating cross-family token verifier config for %q (family %q): %w", tvIn.ContainerName, remoteFamily, remoteErr)
			}
			localEnv.DataStore = remoteOutput.DataStore.Seal()
		}

		tokenVerifierCfg, cfgErr := ccvdeployment.GetTokenVerifierConfig(localEnv.DataStore, tvIn.ContainerName)
		if cfgErr != nil {
			return nil, nil, fmt.Errorf("tokenverifier: getting token verifier config: %w", cfgErr)
		}

		tokenVerifierCfg.TokenVerifiers = dropUnreachableVerifiers(tokenVerifierCfg.TokenVerifiers, familySelectors)
		inputs[i].GeneratedConfig = tokenVerifierCfg
	}

	modifiers := chainreg.GetRegistry().GetTokenVerifierModifiers()
	for _, tvIn := range inputs {
		if tvIn == nil || tvIn.Mode != services.Standalone {
			continue
		}
		tvIn := services.ApplyTokenVerifierDefaults(*tvIn)
		if tvIn.Bootstrap == nil {
			tvIn.Bootstrap = &services.BootstrapInput{}
		}
		monitoring := topology.Monitoring
		fmt.Printf("tokenverifier: monitoring: %+v\n", monitoring)
		tvIn.Bootstrap.Monitoring = &monitoring
		out, launchErr := services.NewTokenVerifier(&tvIn, blockchainOutputs, modifiers)
		if launchErr != nil {
			return nil, nil, fmt.Errorf("tokenverifier: launching %q: %w", tvIn.ContainerName, launchErr)
		}
		tvIn.Out = out
	}

	return map[string]any{Key: inputs}, nil, nil
}

// dropUnreachableVerifiers removes any verifier-type entry (CCTP or Lombard) whose
// resolved verifier-resolver addresses have no chain in common with localSelectors:
// an instance can never coordinate a verifier type it has no locally-reachable chains for.
func dropUnreachableVerifiers(verifiers []token.VerifierConfig, localSelectors []uint64) []token.VerifierConfig {
	local := make(map[string]struct{}, len(localSelectors))
	for _, sel := range localSelectors {
		local[strconv.FormatUint(sel, 10)] = struct{}{}
	}

	reachable := make([]token.VerifierConfig, 0, len(verifiers))
	for _, vc := range verifiers {
		var resolvers map[string]any
		switch {
		case vc.CCTPConfig != nil:
			resolvers = vc.CCTPConfig.VerifierResolvers
		case vc.LombardConfig != nil:
			resolvers = vc.LombardConfig.VerifierResolvers
		}
		hasLocalChain := false
		for chainSelectorStr := range resolvers {
			if _, ok := local[chainSelectorStr]; ok {
				hasLocalChain = true
				break
			}
		}
		if hasLocalChain {
			reachable = append(reachable, vc)
		}
	}
	return reachable
}

// selectorsForFamily filters selectors down to those belonging to family, by cross-referencing
// each selector's registered chain details. Order is not guaranteed to match the input.
func selectorsForFamily(selectors []uint64, family string) []uint64 {
	var filtered []uint64
	for _, sel := range selectors {
		selFamily, err := chainsel.GetSelectorFamily(sel)
		if err != nil {
			continue
		}
		if selFamily == family {
			filtered = append(filtered, sel)
		}
	}
	return filtered
}

func decode(raw any) ([]*services.TokenVerifierInput, error) {
	inputs, err := devenvruntime.DecodeConfig[[]*services.TokenVerifierInput](raw, Key)
	if err != nil {
		return nil, err
	}
	for i, in := range inputs {
		if err := devenvruntime.CheckConfigVersion(in.Version, Version); err != nil {
			return nil, fmt.Errorf("token_verifier entry %d: %w", i, err)
		}
	}
	return inputs, nil
}
