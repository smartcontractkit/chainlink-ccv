package monitoring

import (
	"context"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	commonv1 "github.com/smartcontractkit/chainlink-protos/node-platform/common/v1"
)

// Mirrors the core node's plugin relayer config emitter
// (chainlink-common/pkg/loop/plugin_relayer_emitter.go): same beholder attributes, emit interval,
// and endpoint normalization, so standalone events match core node events downstream.
const (
	beholderDomain     = "node-platform"
	beholderEntity     = "common.v1.ChainPluginConfig"
	beholderDataSchema = "/node-platform/common/v1"

	chainPluginConfigEmitterName = "ChainPluginConfigEmitter"
)

// DefaultChainPluginConfigEmitInterval matches the core node's emit interval.
const DefaultChainPluginConfigEmitInterval = time.Minute * 3

// ChainPluginConfigEmitter periodically emits the ChainPluginConfig beholder event — CSA public
// key, chain ID, and normalized RPC endpoints — as a core node relayer does. Chain families start
// one per chain runtime; no gating needed — a disabled Beholder makes the global emitter a no-op.
type ChainPluginConfigEmitter struct {
	services.Service
	eng *services.Engine

	csaPublicKey string
	chainID      string
	nodes        []*commonv1.Node
	interval     time.Duration
}

// NewChainPluginConfigEmitter constructs the emitter for one chain. An empty csaPublicKey falls
// back to the beholder client's configured auth key. rawNodes maps each RPC node to its endpoints
// by family-chosen label; endpoints are normalized to scheme://host before emission.
func NewChainPluginConfigEmitter(lggr logger.Logger, csaPublicKey, chainID string, rawNodes []map[string]string) *ChainPluginConfigEmitter {
	if csaPublicKey == "" {
		csaPublicKey = beholder.GetClient().Config.AuthPublicKeyHex
		if csaPublicKey == "" {
			lggr.Warn("csa_public_key not configured for chain plugin config emitter")
		}
	}
	if chainID == "" {
		lggr.Warn("chain_id not configured for chain plugin config emitter")
	}

	emitter := &ChainPluginConfigEmitter{
		csaPublicKey: csaPublicKey,
		chainID:      chainID,
		nodes:        normalizeNodes(rawNodes),
		interval:     DefaultChainPluginConfigEmitInterval,
	}

	emitter.Service, emitter.eng = services.Config{
		Name:  chainPluginConfigEmitterName,
		Start: emitter.start,
	}.NewServiceEngine(lggr)

	return emitter
}

func (e *ChainPluginConfigEmitter) start(ctx context.Context) error {
	if e.interval <= 0 {
		e.interval = DefaultChainPluginConfigEmitInterval
	}
	e.eng.Infow(
		"Starting chain plugin config emitter",
		"interval", e.interval,
		"chainID", e.chainID,
		"csaPublicKeyPresent", e.csaPublicKey != "",
		"nodes", len(e.nodes),
	)
	e.eng.GoTick(services.NewTicker(e.interval), e.emit)
	return nil
}

func (e *ChainPluginConfigEmitter) emit(ctx context.Context) {
	payload := e.buildConfig()
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		e.eng.Errorw(
			"failed to marshal ChainPluginConfig",
			"err", err,
			"chainID", e.chainID,
			"nodes", len(payload.Nodes),
		)
		return
	}

	e.eng.Debugw(
		"Emitting ChainPluginConfig",
		"payloadBytes", len(payloadBytes),
		"chainID", e.chainID,
		"nodes", len(payload.Nodes),
	)

	err = beholder.GetEmitter().Emit(ctx, payloadBytes,
		beholder.AttrKeyDomain, beholderDomain,
		beholder.AttrKeyEntity, beholderEntity,
		beholder.AttrKeyDataSchema, beholderDataSchema,
	)
	if err != nil {
		e.eng.Errorw(
			"failed to emit ChainPluginConfig",
			"err", err,
			"payloadBytes", len(payloadBytes),
			"chainID", e.chainID,
			"nodes", len(payload.Nodes),
		)
		return
	}

	e.eng.Debugw(
		"Emitted ChainPluginConfig",
		"payloadBytes", len(payloadBytes),
		"chainID", e.chainID,
		"nodes", len(payload.Nodes),
	)
}

func (e *ChainPluginConfigEmitter) buildConfig() *commonv1.ChainPluginConfig {
	return &commonv1.ChainPluginConfig{
		CsaPublicKey: e.csaPublicKey,
		ChainId:      e.chainID,
		Nodes:        e.nodes,
	}
}

// normalizeNodes sanitizes and filters URL map values for node entries.
func normalizeNodes(rawNodes []map[string]string) []*commonv1.Node {
	if len(rawNodes) == 0 {
		return nil
	}

	out := make([]*commonv1.Node, 0, len(rawNodes))
	for _, raw := range rawNodes {
		normalized := normalizeEndpoints(raw)
		if len(normalized) == 0 {
			continue
		}
		out = append(out, &commonv1.Node{Urls: normalized})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeEndpoints sanitizes and filters URL map values.
func normalizeEndpoints(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return nil
	}

	out := make(map[string]string, len(raw))
	for key, item := range raw {
		if strings.TrimSpace(key) == "" {
			continue
		}
		normalized := normalizeEndpoint(item)
		if normalized == "" {
			continue
		}
		out[key] = normalized
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeEndpoint returns only scheme://host (no port/userinfo/path/query/fragment).
// If the input has no scheme, the host-only string is returned.
func normalizeEndpoint(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	scheme, host, err := parseOriginURL(s)
	if err != nil {
		return ""
	}
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if scheme == "" {
		return host
	}
	return scheme + "://" + host
}

// parseOriginURL is based on go-ethereum's parseOriginURL, adapted for our needs:
// - returns only scheme and hostname (port is discarded)
// - handles schemeless inputs with userinfo/port/path
func parseOriginURL(origin string) (string, string, error) {
	parsedURL, err := url.Parse(strings.ToLower(origin))
	if err != nil {
		return "", "", err
	}
	if strings.Contains(origin, "://") {
		return parsedURL.Scheme, parsedURL.Hostname(), nil
	}

	if hostURL, err := url.Parse("//" + origin); err == nil {
		if host := hostURL.Hostname(); host != "" {
			return "", host, nil
		}
	}

	hostname := parsedURL.Scheme
	if hostname == "" {
		hostname = origin
	}
	return "", hostname, nil
}
