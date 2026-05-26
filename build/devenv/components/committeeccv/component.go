package committeeccv

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	devenvcommon "github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	ccdeploy "github.com/smartcontractkit/chainlink-ccv/build/devenv/deploy"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/util"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvadapters "github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/commit"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

const configKey = "aggregator"

func init() {
	if err := devenvruntime.Register(configKey, factory); err != nil {
		panic(fmt.Sprintf("committeeccv component: %v", err))
	}
}

func factory(_ map[string]any) (devenvruntime.Component, error) {
	return &component{}, nil
}

type component struct{}

func (c *component) ValidateConfig(_ any) error { return nil }

// RunPhase3 performs the full CommitteeCCV setup:
//  1. Generates HMAC client credentials for each aggregator.
//  2. Launches standalone verifier containers and registers them with JD.
//  3. Generates shared TLS certificates from aggregator container names.
//  4. Assigns TLS certificates to aggregators and enriches the topology with verifier keys.
//  5. Generates aggregator committee configuration via changeset.
//  6. Launches full aggregator containers.
//  7. Generates verifier job specs and emits JobProposalEffect for each standalone verifier.
//
// Outputs "aggregators", "verifiers", and "shared_tls_certs" for Phase 4 (Indexer) consumption.
func (c *component) RunPhase3(
	ctx context.Context,
	globalConfig map[string]any,
	componentConfig any,
	priorOutputs map[string]any,
) (map[string]any, []devenvruntime.Effect, error) {
	aggregators, err := decodeAggregators(componentConfig)
	if err != nil {
		return nil, nil, err
	}
	verifiers, err := decodeVerifiers(globalConfig["verifier"])
	if err != nil {
		return nil, nil, err
	}

	if len(aggregators) == 0 && len(verifiers) == 0 {
		return map[string]any{}, nil, nil
	}

	jdInfra, ok := priorOutputs["jd"].(*jobs.JDInfrastructure)
	if !ok || jdInfra == nil {
		return nil, nil, fmt.Errorf("committeeccv: jd not found in phase outputs")
	}
	blockchainOutputs, ok := priorOutputs["blockchainOutputs"].([]*ctfblockchain.Output)
	if !ok {
		return nil, nil, fmt.Errorf("committeeccv: blockchainOutputs not found in phase outputs")
	}
	e, ok := priorOutputs["_env"].(*deployment.Environment)
	if !ok || e == nil {
		return nil, nil, fmt.Errorf("committeeccv: _env not found in phase outputs")
	}
	topology, ok := priorOutputs["_topology"].(*ccvdeployment.EnvironmentTopology)
	if !ok || topology == nil {
		return nil, nil, fmt.Errorf("committeeccv: _topology not found in phase outputs")
	}
	ds, ok := priorOutputs["_ds"].(datastore.MutableDataStore)
	if !ok {
		return nil, nil, fmt.Errorf("committeeccv: _ds not found in phase outputs")
	}
	impls, _ := priorOutputs["_impls"].([]cciptestinterfaces.CCIP17Configuration)
	blockchains, _ := priorOutputs["blockchains"].([]*ctfblockchain.Input)
	useLegacyConfigureLane, _ := priorOutputs["_use_legacy_configure_lane"].(bool)

	// Step 1: Generate HMAC client credentials for all aggregators before launching verifiers.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		creds, cerr := agg.EnsureClientCredentials()
		if cerr != nil {
			return nil, nil, fmt.Errorf("committeeccv: failed to ensure client credentials for aggregator %s: %w", agg.CommitteeName, cerr)
		}
		if agg.Out == nil {
			agg.Out = &services.AggregatorOutput{}
		}
		agg.Out.ClientCredentials = creds
	}

	// Step 2: Launch standalone verifier containers (reads HMAC creds from agg.Out).
	if err := committeeverifier.LaunchStandaloneVerifiers(
		verifiers, aggregators, blockchainOutputs, jdInfra,
		chainreg.GetRegistry().GetVerifierModifiers(),
	); err != nil {
		return nil, nil, fmt.Errorf("committeeccv: failed to launch standalone verifiers: %w", err)
	}
	if err := committeeverifier.RegisterStandaloneVerifiersWithJD(ctx, verifiers, jdInfra.OffchainClient); err != nil {
		return nil, nil, fmt.Errorf("committeeccv: failed to register standalone verifiers with JD: %w", err)
	}

	// Step 3: Generate shared TLS certificates from aggregator container names.
	var sharedTLSCerts *services.TLSCertPaths
	if len(aggregators) > 0 {
		var allHostnames []string
		for _, agg := range aggregators {
			if agg == nil {
				continue
			}
			nginxName := fmt.Sprintf("%s-%s", agg.InstanceName(), services.AggregatorNginxContainerNameSuffix)
			aggName := fmt.Sprintf("%s-%s", agg.InstanceName(), services.AggregatorContainerNameSuffix)
			allHostnames = append(allHostnames, nginxName, aggName)
		}
		allHostnames = append(allHostnames, "localhost")
		tlsCertDir := filepath.Join(util.CCVConfigDir(), "tls-shared")
		sharedTLSCerts, err = services.GenerateTLSCertificates(allHostnames, tlsCertDir)
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: failed to generate shared TLS certificates: %w", err)
		}
	}

	// Step 4: Assign shared TLS certificates to each aggregator.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		agg.SharedTLSCerts = sharedTLSCerts
	}

	// Step 5: Enrich topology with verifier signer keys.
	if len(verifiers) > 0 {
		ccdeploy.EnrichTopologyWithVerifiers(topology, verifiers)
	}

	// Step 5b: Configure lanes. This requires verifiers to be registered in JD (done above)
	// because ApplyVerifierConfig fetches verifier signing keys from JD by node ID.
	if len(impls) > 0 && len(blockchains) > 0 {
		selectors, _ := priorOutputs["_selectors"].([]uint64)
		var connectErr error
		if useLegacyConfigureLane {
			connectErr = ccdeploy.ConnectAllChainsLegacy(impls, blockchains, selectors, e, topology)
		} else {
			connectErr = ccdeploy.ConnectAllChainsCanonical(impls, blockchains, selectors, e, topology)
		}
		if connectErr != nil {
			return nil, nil, fmt.Errorf("committeeccv: configure lanes: %w", connectErr)
		}
	}

	// Step 6: Generate aggregator committee configuration.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		instanceName := agg.InstanceName()
		committee, ok := topology.NOPTopology.Committees[agg.CommitteeName]
		if !ok {
			return nil, nil, fmt.Errorf("committeeccv: committee %q not found in topology", agg.CommitteeName)
		}
		cs := ccvchangesets.GenerateAggregatorConfig(ccvadapters.GetRegistry())
		output, err := cs.Apply(*e, ccvchangesets.GenerateAggregatorConfigInput{
			ServiceIdentifier:  instanceName + "-aggregator",
			CommitteeQualifier: agg.CommitteeName,
			ChainSelectors:     ccvchangesets.CommitteeChainSelectorsFromTopology(committee),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: GenerateAggregatorConfig for %q: %w", instanceName, err)
		}
		aggCfg, err := ccvdeployment.GetAggregatorConfig(output.DataStore.Seal(), instanceName+"-aggregator")
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: get aggregator config for %q: %w", instanceName, err)
		}
		agg.GeneratedCommittee = aggCfg
		e.DataStore = output.DataStore.Seal()
	}

	// Step 7: Launch full aggregator containers.
	for _, agg := range aggregators {
		if agg == nil {
			continue
		}
		out, err := services.NewAggregator(agg)
		if err != nil {
			return nil, nil, fmt.Errorf("committeeccv: starting aggregator %q: %w", agg.CommitteeName, err)
		}
		agg.Out = out
	}

	// Step 8: Generate verifier job specs and emit job proposal effects.
	effects, err := buildVerifierJobSpecEffects(e, verifiers, topology, sharedTLSCerts, blockchainOutputs, ds)
	if err != nil {
		return nil, nil, err
	}

	return map[string]any{
		"aggregators":      aggregators,
		"verifiers":        verifiers,
		"shared_tls_certs": sharedTLSCerts,
	}, effects, nil
}

type verifierJobSpec struct {
	Name                    string `toml:"name"`
	ExternalJobID           string `toml:"externalJobID"`
	SchemaVersion           int    `toml:"schemaVersion"`
	Type                    string `toml:"type"`
	CommitteeVerifierConfig string `toml:"committeeVerifierConfig"`
}

func (vjs verifierJobSpec) toBootstrapJobSpec() bootstrap.JobSpec {
	return bootstrap.JobSpec{
		Name:          vjs.Name,
		ExternalJobID: vjs.ExternalJobID,
		SchemaVersion: vjs.SchemaVersion,
		Type:          vjs.Type,
		AppConfig:     vjs.CommitteeVerifierConfig,
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateDisableFinalityCheckers(committeeName string, verifiers []*committeeverifier.Input) (map[string][]string, error) {
	if len(verifiers) == 0 {
		return nil, nil
	}
	result := make(map[string][]string)
	for _, ver := range verifiers {
		if existing, ok := result[ver.ChainFamily]; ok {
			if !stringSlicesEqual(existing, ver.DisableFinalityCheckers) {
				return nil, fmt.Errorf(
					"verifiers in committee %q within the same chain family %s have inconsistent disable_finality_checkers settings",
					committeeName, ver.ChainFamily,
				)
			}
		}
		result[ver.ChainFamily] = ver.DisableFinalityCheckers
	}
	return result, nil
}

func validateVerifierNodeIndices(committeeName string, verifiers []*committeeverifier.Input) error {
	seen := make(map[int]string, len(verifiers))
	for _, ver := range verifiers {
		if existing, dup := seen[ver.NodeIndex]; dup {
			return fmt.Errorf(
				"committee %q: verifiers %q and %q both have node_index=%d — "+
					"node_index must be unique within a committee",
				committeeName, existing, ver.ContainerName, ver.NodeIndex,
			)
		}
		seen[ver.NodeIndex] = ver.ContainerName
	}
	return nil
}

// buildVerifierJobSpecEffects generates verifier job specs via changeset and emits
// JobProposalEffect for each standalone verifier. It also sets GeneratedConfig,
// GeneratedJobSpecs, VerifierID, and TLSCACertFile as side effects on the verifier inputs.
func buildVerifierJobSpecEffects(
	e *deployment.Environment,
	verifiers []*committeeverifier.Input,
	topology *ccvdeployment.EnvironmentTopology,
	sharedTLSCerts *services.TLSCertPaths,
	blockchainOutputs []*ctfblockchain.Output,
	ds datastore.MutableDataStore,
) ([]devenvruntime.Effect, error) {
	if len(verifiers) == 0 {
		return nil, nil
	}

	verifiersByCommittee := make(map[string][]*committeeverifier.Input)
	for _, ver := range verifiers {
		verifiersByCommittee[ver.CommitteeName] = append(verifiersByCommittee[ver.CommitteeName], ver)
	}

	var effects []devenvruntime.Effect
	for committeeName, committeeVerifiers := range verifiersByCommittee {
		disableFinalityCheckersPerFamily, err := validateDisableFinalityCheckers(committeeName, committeeVerifiers)
		if err != nil {
			return nil, err
		}

		families := make(map[string]struct{})
		for _, ver := range committeeVerifiers {
			families[ver.ChainFamily] = struct{}{}
		}

		for family := range families {
			verNOPAliases := make([]ccvshared.NOPAlias, 0, len(committeeVerifiers))
			for _, ver := range committeeVerifiers {
				if ver.ChainFamily == family {
					verNOPAliases = append(verNOPAliases, ccvshared.NOPAlias(ver.NOPAlias))
				}
			}

			committee, ok := topology.NOPTopology.Committees[committeeName]
			if !ok {
				return nil, fmt.Errorf("committeeccv: committee %q not found in topology", committeeName)
			}
			cs := ccvchangesets.ApplyVerifierConfig(ccvadapters.GetRegistry())
			output, err := cs.Apply(*e, ccvchangesets.ApplyVerifierConfigInput{
				CommitteeQualifier:       committeeName,
				DefaultExecutorQualifier: devenvcommon.DefaultExecutorQualifier,
				NOPs:                     ccvchangesets.NOPInputsFromTopology(topology),
				Committee:                ccvchangesets.CommitteeInputFromTopologyPerFamily(committee, family),
				PyroscopeURL:             topology.PyroscopeURL,
				Monitoring:               topology.Monitoring,
				TargetNOPs:               verNOPAliases,
				DisableFinalityCheckers:  disableFinalityCheckersPerFamily[family],
			})
			if err != nil {
				return nil, fmt.Errorf("committeeccv: generating verifier configs for committee %s: %w", committeeName, err)
			}
			if err := ds.Merge(output.DataStore.Seal()); err != nil {
				return nil, fmt.Errorf("committeeccv: merging verifier job specs datastore: %w", err)
			}

			aggNames, err := topology.GetAggregatorNamesForCommittee(committeeName)
			if err != nil {
				return nil, err
			}
			if len(aggNames) == 0 {
				return nil, fmt.Errorf("committeeccv: committee %q has no aggregators in topology", committeeName)
			}
			if err := validateVerifierNodeIndices(committeeName, committeeVerifiers); err != nil {
				return nil, err
			}

			for _, ver := range committeeVerifiers {
				if ver.ChainFamily != family {
					continue
				}

				allJobSpecs := make([]bootstrap.JobSpec, 0, len(aggNames))
				for _, aggName := range aggNames {
					jobSpecID := ccvshared.NewVerifierJobID(ccvshared.NOPAlias(ver.NOPAlias), aggName, ccvshared.VerifierJobScope{CommitteeQualifier: committeeName})
					job, err := ccvdeployment.GetJob(output.DataStore.Seal(), ccvshared.NOPAlias(ver.NOPAlias), jobSpecID.ToJobID())
					if err != nil {
						return nil, fmt.Errorf("committeeccv: getting verifier job spec for %s agg %s: %w", ver.ContainerName, aggName, err)
					}
					var spec verifierJobSpec
					if err := toml.Unmarshal([]byte(job.Spec), &spec); err != nil {
						return nil, fmt.Errorf("committeeccv: decoding verifier job spec for %s: %w", ver.ContainerName, err)
					}
					allJobSpecs = append(allJobSpecs, spec.toBootstrapJobSpec())
				}

				ver.GeneratedJobSpecs = allJobSpecs

				ownedAggIdx := ver.NodeIndex % len(aggNames)
				var verCfg commit.Config
				if err := toml.Unmarshal([]byte(allJobSpecs[ownedAggIdx].AppConfig), &verCfg); err != nil {
					return nil, fmt.Errorf("committeeccv: parsing verifier config from job spec: %w", err)
				}
				configBytes, err := toml.Marshal(verCfg)
				if err != nil {
					return nil, fmt.Errorf("committeeccv: marshaling verifier config: %w", err)
				}
				ver.GeneratedConfig = string(configBytes)
				if ver.Out != nil {
					ver.Out.VerifierID = verCfg.VerifierID
				}
				if sharedTLSCerts != nil && !ver.InsecureAggregatorConnection {
					ver.TLSCACertFile = sharedTLSCerts.CACertFile
				}

				if ver.Mode != services.Standalone {
					continue
				}
				if ver.Out == nil || ver.Out.JDNodeID == "" {
					return nil, fmt.Errorf("committeeccv: verifier %s not registered with JD (missing JDNodeID)", ver.NOPAlias)
				}
				reg, loaderErr := chainreg.GetRegistry().Get(ver.ChainFamily)
				if loaderErr != nil {
					return nil, fmt.Errorf("committeeccv: chain registration for verifier %s: %w", ver.NOPAlias, loaderErr)
				}
				if reg.ChainConfigLoader == nil {
					return nil, fmt.Errorf("committeeccv: chain config loader for family %s not found", ver.ChainFamily)
				}
				blockchainInfos, loaderErr := reg.ChainConfigLoader(blockchainOutputs)
				if loaderErr != nil {
					return nil, fmt.Errorf("committeeccv: loading chain config for verifier %s: %w", ver.NOPAlias, loaderErr)
				}
				baseSpec := allJobSpecs[ver.NodeIndex%len(allJobSpecs)]
				jobSpec, specErr := committeeverifier.RebuildVerifierJobSpecWithBlockchainInfos(baseSpec, blockchainInfos)
				if specErr != nil {
					return nil, fmt.Errorf("committeeccv: building job spec for verifier %s: %w", ver.NOPAlias, specErr)
				}
				effects = append(effects, devenvruntime.JobProposalEffect{
					NOPAlias: ver.NOPAlias,
					NodeID:   ver.Out.JDNodeID,
					JobSpec:  jobSpec,
				})
			}
		}
	}

	return effects, nil
}

// decodeAggregators round-trips the raw TOML []any into []*services.AggregatorInput.
func decodeAggregators(raw any) ([]*services.AggregatorInput, error) {
	b, err := toml.Marshal(struct {
		V any `toml:"aggregator"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding aggregator config: %w", err)
	}
	var wrapper struct {
		V []*services.AggregatorInput `toml:"aggregator"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding aggregator config: %w", err)
	}
	return wrapper.V, nil
}

// decodeVerifiers round-trips the raw TOML []any into []*committeeverifier.Input.
func decodeVerifiers(raw any) ([]*committeeverifier.Input, error) {
	if raw == nil {
		return nil, nil
	}
	b, err := toml.Marshal(struct {
		V any `toml:"verifier"`
	}{V: raw})
	if err != nil {
		return nil, fmt.Errorf("re-encoding verifier config: %w", err)
	}
	var wrapper struct {
		V []*committeeverifier.Input `toml:"verifier"`
	}
	if err := toml.Unmarshal(b, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding verifier config: %w", err)
	}
	return wrapper.V, nil
}
