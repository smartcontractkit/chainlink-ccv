package evmconfig

import evmtoml "github.com/smartcontractkit/chainlink-evm/pkg/config/toml"

// BroadcastEndpointSummary counts legacy and standalone write endpoints without exposing URLs.
type BroadcastEndpointSummary struct {
	ChainID                    string `json:"chain_id"`
	LegacyEndpoints            int    `json:"legacy_endpoints"`
	StandaloneEndpoints        int    `json:"standalone_endpoints"`
	SendOnlyEndpointsDropped   int    `json:"send_only_endpoints_dropped"`
	ExtraWriteEndpointsDropped int    `json:"extra_write_endpoints_dropped"`
	ReviewRequired             bool   `json:"review_required"`
}

func summarizeBroadcastEndpoints(chainID string, legacy evmtoml.EVMNodes, standalone []Node) BroadcastEndpointSummary {
	summary := BroadcastEndpointSummary{ChainID: chainID, StandaloneEndpoints: len(standalone)}
	for _, node := range legacy {
		if node == nil {
			continue
		}
		endpoints := 0
		if node.HTTPURL != nil {
			endpoints++
		}
		if node.HTTPURLExtraWrite != nil {
			endpoints++
			summary.ExtraWriteEndpointsDropped++
		}
		summary.LegacyEndpoints += endpoints
		if node.SendOnly != nil && *node.SendOnly {
			summary.SendOnlyEndpointsDropped += endpoints
		}
	}
	summary.ReviewRequired = summary.StandaloneEndpoints < summary.LegacyEndpoints
	return summary
}
