package offchainloader

import (
	"github.com/smartcontractkit/chainlink-ccip/deployment/v1_7_0/offchain"
	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/indexer/pkg/config"
	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	verifier "github.com/smartcontractkit/chainlink-ccv/verifier/pkg"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

func GetAggregatorConfig(ds datastore.DataStore, id string) (*model.Committee, error) {
	ccipCfg, err := offchain.GetAggregatorConfig(ds, id)
	if err != nil {
		return nil, err
	}
	return convertCommittee(ccipCfg), nil
}

func GetIndexerConfig(ds datastore.DataStore, id string) (*config.GeneratedConfig, error) {
	ccipCfg, err := offchain.GetIndexerConfig(ds, id)
	if err != nil {
		return nil, err
	}
	return convertIndexerConfig(ccipCfg), nil
}

func GetTokenVerifierConfig(ds datastore.DataStore, id string) (*token.Config, error) {
	ccipCfg, err := offchain.GetTokenVerifierConfig(ds, id)
	if err != nil {
		return nil, err
	}
	return convertTokenVerifierConfig(ccipCfg), nil
}

func convertCommittee(src *offchain.Committee) *model.Committee {
	if src == nil {
		return nil
	}
	dst := &model.Committee{
		DestinationVerifiers: src.DestinationVerifiers,
	}
	if src.QuorumConfigs != nil {
		dst.QuorumConfigs = make(map[model.SourceSelector]*model.QuorumConfig, len(src.QuorumConfigs))
		for k, qc := range src.QuorumConfigs {
			dst.QuorumConfigs[k] = convertQuorumConfig(qc)
		}
	}
	return dst
}

func convertQuorumConfig(src *offchain.QuorumConfig) *model.QuorumConfig {
	if src == nil {
		return nil
	}
	signers := make([]model.Signer, len(src.Signers))
	for i, s := range src.Signers {
		signers[i] = model.Signer{Address: s.Address}
	}
	return &model.QuorumConfig{
		SourceVerifierAddress: src.SourceVerifierAddress,
		Signers:               signers,
		Threshold:             src.Threshold,
	}
}

func convertIndexerConfig(src *offchain.IndexerGeneratedConfig) *config.GeneratedConfig {
	if src == nil {
		return nil
	}
	verifiers := make([]config.GeneratedVerifierConfig, len(src.Verifiers))
	for i, v := range src.Verifiers {
		verifiers[i] = config.GeneratedVerifierConfig{
			Name:            v.Name,
			IssuerAddresses: v.IssuerAddresses,
		}
	}
	return &config.GeneratedConfig{Verifier: verifiers}
}

func convertTokenVerifierConfig(src *offchain.TokenVerifierGeneratedConfig) *token.Config {
	if src == nil {
		return nil
	}
	dst := &token.Config{
		PyroscopeURL: src.PyroscopeURL,
		CommitteeConfig: chainaccess.CommitteeConfig{
			OnRampAddresses:    src.OnRampAddresses,
			RMNRemoteAddresses: src.RMNRemoteAddresses,
		},
		Monitoring: verifier.MonitoringConfig{
			Enabled: src.Monitoring.Enabled,
			Type:    src.Monitoring.Type,
			Beholder: verifier.BeholderConfig{
				InsecureConnection:       src.Monitoring.Beholder.InsecureConnection,
				CACertFile:               src.Monitoring.Beholder.CACertFile,
				OtelExporterGRPCEndpoint: src.Monitoring.Beholder.OtelExporterGRPCEndpoint,
				OtelExporterHTTPEndpoint: src.Monitoring.Beholder.OtelExporterHTTPEndpoint,
				LogStreamingEnabled:      src.Monitoring.Beholder.LogStreamingEnabled,
				MetricReaderInterval:     src.Monitoring.Beholder.MetricReaderInterval,
				TraceSampleRatio:         src.Monitoring.Beholder.TraceSampleRatio,
				TraceBatchTimeout:        src.Monitoring.Beholder.TraceBatchTimeout,
			},
		},
	}
	dst.TokenVerifiers = make([]token.VerifierConfig, len(src.TokenVerifiers))
	for i, tv := range src.TokenVerifiers {
		vc := token.VerifierConfig{
			VerifierID: tv.VerifierID,
			Type:       tv.Type,
			Version:    tv.Version,
		}
		if tv.CCTP != nil {
			vc.CCTPConfig = convertCCTPConfig(tv.CCTP)
		}
		if tv.Lombard != nil {
			vc.LombardConfig = convertLombardConfig(tv.Lombard)
		}
		dst.TokenVerifiers[i] = vc
	}
	return dst
}

func convertCCTPConfig(src *offchain.CCTPVerifierConfig) *cctp.CCTPConfig {
	if src == nil {
		return nil
	}
	dst := &cctp.CCTPConfig{
		AttestationAPI:         src.AttestationAPI,
		AttestationAPITimeout:  src.AttestationAPITimeout,
		AttestationAPIInterval: src.AttestationAPIInterval,
		AttestationAPICooldown: src.AttestationAPICooldown,
		VerifierVersion:        protocol.ByteSlice(src.VerifierVersion),
	}
	if src.Verifiers != nil {
		dst.Verifiers = toAnyMap(src.Verifiers)
	}
	if src.VerifierResolvers != nil {
		dst.VerifierResolvers = toAnyMap(src.VerifierResolvers)
	}
	return dst
}

func convertLombardConfig(src *offchain.LombardVerifierConfig) *lombard.LombardConfig {
	if src == nil {
		return nil
	}
	dst := &lombard.LombardConfig{
		AttestationAPI:          src.AttestationAPI,
		AttestationAPITimeout:   src.AttestationAPITimeout,
		AttestationAPIInterval:  src.AttestationAPIInterval,
		AttestationAPIBatchSize: src.AttestationAPIBatchSize,
		VerifierVersion:         protocol.ByteSlice(src.VerifierVersion),
	}
	if src.VerifierResolvers != nil {
		dst.VerifierResolvers = toAnyMap(src.VerifierResolvers)
	}
	return dst
}

func toAnyMap(src map[string]string) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
