package changesets

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/lombard"

	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	"github.com/smartcontractkit/chainlink-ccv/deployment/adapters"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

const (
	TestnetCCTPAttestationAPI    = "https://iris-api-sandbox.circle.com"
	TestnetLombardAttestationAPI = "https://gastald-testnet.prod.lombard.finance/api/"
	MainnetCCTPAttestationAPI    = "https://iris-api.circle.com"
	MainnetLombardAttestationAPI = "https://mainnet.prod.lombard.finance/api/"
)

var (
	// bytes4(keccak256("CCTPVerifier 2.0.0")) = 0x35a25838.
	DefaultCCTPVerifierVersion = mustDecodeHex("35a25838")
	// bytes4(keccak256("LombardVerifier 2.0.0")) = 0xeba55588.
	DefaultLombardVerifierVersion = mustDecodeHex("eba55588")
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("failed to decode hex %q: %v", s, err))
	}
	return b
}

type LombardConfigInput struct {
	Qualifier               string
	VerifierID              string
	VerifierVersion         []byte
	AttestationAPI          string
	AttestationAPITimeout   time.Duration
	AttestationAPIInterval  time.Duration
	AttestationAPIBatchSize int
}

type CCTPConfigInput struct {
	Qualifier              string
	VerifierID             string
	VerifierVersion        []byte
	AttestationAPI         string
	AttestationAPITimeout  time.Duration
	AttestationAPIInterval time.Duration
	AttestationAPICooldown time.Duration
}

type GenerateTokenVerifierConfigInput struct {
	ServiceIdentifier string
	ChainSelectors    []uint64
	PyroscopeURL      string
	Monitoring        ccvdeployment.MonitoringConfig
	Lombard           LombardConfigInput
	CCTP              CCTPConfigInput
}

func GenerateTokenVerifierConfig(registry *adapters.Registry) deployment.ChangeSetV2[GenerateTokenVerifierConfigInput] {
	validate := func(e deployment.Environment, cfg GenerateTokenVerifierConfigInput) error {
		if cfg.ServiceIdentifier == "" {
			return fmt.Errorf("service identifier is required")
		}
		envSelectors := e.BlockChains.ListChainSelectors()
		for _, s := range cfg.ChainSelectors {
			if !slices.Contains(envSelectors, s) {
				return fmt.Errorf("selector %d is not available in environment", s)
			}
		}
		return nil
	}

	apply := func(e deployment.Environment, cfg GenerateTokenVerifierConfigInput) (deployment.ChangesetOutput, error) {
		selectors := cfg.ChainSelectors
		if len(selectors) == 0 {
			selectors = e.BlockChains.ListChainSelectors()
		}

		isProd := shared.IsProductionEnvironment(e.Name)
		lombardCfg := applyLombardDefaults(cfg.Lombard, isProd)
		cctpCfg := applyCCTPDefaults(cfg.CCTP, isProd)

		onRampAddresses := make(map[string]string)
		rmnRemoteAddresses := make(map[string]string)
		cctpVerifierAddresses := make(map[string]string)
		cctpVerifierResolverAddresses := make(map[string]string)
		lombardVerifierResolverAddresses := make(map[string]string)

		for _, sel := range selectors {
			a, err := registry.GetByChain(sel)
			if err != nil {
				return deployment.ChangesetOutput{}, err
			}
			if a.TokenVerifier == nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("no token verifier config adapter registered for chain %d", sel)
			}

			addrs, err := a.TokenVerifier.ResolveTokenVerifierAddresses(
				e.DataStore, sel, cctpCfg.Qualifier, lombardCfg.Qualifier,
			)
			if err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to resolve token verifier addresses for chain %d: %w", sel, err)
			}

			chainSelectorStr := strconv.FormatUint(sel, 10)
			onRampAddresses[chainSelectorStr] = addrs.OnRampAddress
			rmnRemoteAddresses[chainSelectorStr] = addrs.RMNRemoteAddress

			if addrs.CCTPVerifierAddress != "" {
				cctpVerifierAddresses[chainSelectorStr] = addrs.CCTPVerifierAddress
				cctpVerifierResolverAddresses[chainSelectorStr] = addrs.CCTPVerifierResolverAddress
			}
			if addrs.LombardVerifierResolverAddress != "" {
				lombardVerifierResolverAddresses[chainSelectorStr] = addrs.LombardVerifierResolverAddress
			}
		}

		tvConfig := &token.Config{
			PyroscopeURL: cfg.PyroscopeURL,
			CommitteeConfig: chainaccess.CommitteeConfig{
				OnRampAddresses:    onRampAddresses,
				RMNRemoteAddresses: rmnRemoteAddresses,
			},
			TokenVerifiers: []token.VerifierConfig{},
			Monitoring:     cfg.Monitoring,
		}

		if len(cctpVerifierAddresses) > 0 {
			cctpVerifierID := cctpCfg.VerifierID
			if cctpVerifierID == "" {
				cctpVerifierID = fmt.Sprintf("cctp-%s", cctpCfg.Qualifier)
			}
			tvConfig.TokenVerifiers = append(tvConfig.TokenVerifiers, token.VerifierConfig{
				VerifierID: cctpVerifierID,
				Type:       "cctp",
				Version:    "2.0",
				CCTPConfig: &cctp.CCTPConfig{
					AttestationAPI:         cctpCfg.AttestationAPI,
					AttestationAPITimeout:  cctpCfg.AttestationAPITimeout,
					AttestationAPIInterval: cctpCfg.AttestationAPIInterval,
					AttestationAPICooldown: cctpCfg.AttestationAPICooldown,
					VerifierVersion:        protocol.ByteSlice(cctpCfg.VerifierVersion),
					Verifiers:              stringsToAnyMap(cctpVerifierAddresses),
					VerifierResolvers:      stringsToAnyMap(cctpVerifierResolverAddresses),
				},
			})
		}

		if len(lombardVerifierResolverAddresses) > 0 {
			lombardVerifierID := lombardCfg.VerifierID
			if lombardVerifierID == "" {
				lombardVerifierID = fmt.Sprintf("lombard-%s", lombardCfg.Qualifier)
			}
			tvConfig.TokenVerifiers = append(tvConfig.TokenVerifiers, token.VerifierConfig{
				VerifierID: lombardVerifierID,
				Type:       "lombard",
				Version:    "1.0",
				LombardConfig: &lombard.LombardConfig{
					AttestationAPI:          lombardCfg.AttestationAPI,
					AttestationAPITimeout:   lombardCfg.AttestationAPITimeout,
					AttestationAPIInterval:  lombardCfg.AttestationAPIInterval,
					AttestationAPIBatchSize: lombardCfg.AttestationAPIBatchSize,
					VerifierVersion:         protocol.ByteSlice(lombardCfg.VerifierVersion),
					VerifierResolvers:       stringsToAnyMap(lombardVerifierResolverAddresses),
				},
			})
		}

		outputDS := datastore.NewMemoryDataStore()
		if e.DataStore != nil {
			if err := outputDS.Merge(e.DataStore); err != nil {
				return deployment.ChangesetOutput{}, fmt.Errorf("failed to merge existing datastore: %w", err)
			}
		}

		if err := ccvdeployment.SaveTokenVerifierConfig(outputDS, cfg.ServiceIdentifier, tvConfig); err != nil {
			return deployment.ChangesetOutput{}, fmt.Errorf("failed to save token verifier config: %w", err)
		}

		return deployment.ChangesetOutput{
			DataStore: outputDS,
		}, nil
	}

	return deployment.CreateChangeSet(apply, validate)
}

func stringsToAnyMap(src map[string]string) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func applyLombardDefaults(cfg LombardConfigInput, isProd bool) LombardConfigInput {
	if cfg.AttestationAPI == "" {
		if isProd {
			cfg.AttestationAPI = MainnetLombardAttestationAPI
		} else {
			cfg.AttestationAPI = TestnetLombardAttestationAPI
		}
	}
	if cfg.AttestationAPITimeout == 0 {
		cfg.AttestationAPITimeout = 1 * time.Second
	}
	if cfg.AttestationAPIInterval == 0 {
		cfg.AttestationAPIInterval = 100 * time.Millisecond
	}
	if cfg.AttestationAPIBatchSize == 0 {
		cfg.AttestationAPIBatchSize = 20
	}
	if len(cfg.VerifierVersion) == 0 {
		cfg.VerifierVersion = DefaultLombardVerifierVersion
	}
	return cfg
}

func applyCCTPDefaults(cfg CCTPConfigInput, isProd bool) CCTPConfigInput {
	if cfg.AttestationAPI == "" {
		if isProd {
			cfg.AttestationAPI = MainnetCCTPAttestationAPI
		} else {
			cfg.AttestationAPI = TestnetCCTPAttestationAPI
		}
	}
	if cfg.AttestationAPITimeout == 0 {
		cfg.AttestationAPITimeout = 1 * time.Second
	}
	if cfg.AttestationAPIInterval == 0 {
		cfg.AttestationAPIInterval = 100 * time.Millisecond
	}
	if cfg.AttestationAPICooldown == 0 {
		cfg.AttestationAPICooldown = 5 * time.Minute
	}
	if len(cfg.VerifierVersion) == 0 {
		cfg.VerifierVersion = DefaultCCTPVerifierVersion
	}
	return cfg
}
