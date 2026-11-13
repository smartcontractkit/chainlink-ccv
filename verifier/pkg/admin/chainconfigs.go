package admin

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
)

// ChainInspectionResult keeps a chain's inspection separate from its lookup failure.
type ChainInspectionResult struct {
	Selector   protocol.ChainSelector
	Inspection chainaccess.ChainInspection
	Err        error
}

// ChainInspectionProvider supplies effective chain configuration on demand.
type ChainInspectionProvider interface {
	// ChainInspections returns effective chain configuration and per-chain failures.
	ChainInspections(ctx context.Context) []ChainInspectionResult
}

// ChainInspectionSource inspects configured chains through their optional accessor capability.
type ChainInspectionSource struct {
	selectors  []protocol.ChainSelector
	inspectors map[protocol.ChainSelector]chainaccess.ChainInspector
}

// NewChainInspectionSource snapshots selectors and inspectors for the active job.
func NewChainInspectionSource(selectors []protocol.ChainSelector, inspectors map[protocol.ChainSelector]chainaccess.ChainInspector) *ChainInspectionSource {
	return &ChainInspectionSource{
		selectors:  append([]protocol.ChainSelector(nil), selectors...),
		inspectors: inspectors,
	}
}

// ChainInspections returns one result per configured selector, including unsupported chains.
func (s *ChainInspectionSource) ChainInspections(ctx context.Context) []ChainInspectionResult {
	if s == nil {
		return nil
	}
	results := make([]ChainInspectionResult, 0, len(s.selectors))
	for _, selector := range s.selectors {
		result := ChainInspectionResult{Selector: selector, Inspection: chainaccess.ChainInspection{Selector: selector}}
		inspector, ok := s.inspectors[selector]
		if !ok {
			result.Err = errors.New("chain inspection is unavailable for this chain")
			results = append(results, result)
			continue
		}
		inspection, err := inspector.InspectChain(ctx)
		result.Inspection = inspection
		result.Err = err
		results = append(results, result)
	}
	return results
}

func (h *handlers) registerChainConfigRoutes(r *gin.Engine) {
	r.GET("/chains", h.chainConfigsPage)
}

func (h *handlers) chainConfigsPage(c *gin.Context) {
	var results []ChainInspectionResult
	if h.chainSource != nil {
		results = h.chainSource.ChainInspections(c.Request.Context())
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Selector < results[j].Selector })
	vm := views.ChainConfigsVM{Chains: make([]views.ChainConfigVM, 0, len(results))}
	for _, result := range results {
		inspection := result.Inspection
		chain := views.ChainConfigVM{
			Selector: result.Selector.String(), Name: chainDisplayName(result.Selector),
			Family: inspection.Family, ChainID: inspection.ChainID,
			Roles: strings.Join(inspection.Roles, ", "), Diagnostics: inspection.Diagnostics,
		}
		if result.Err != nil {
			chain.Diagnostics = append(chain.Diagnostics, result.Err.Error())
		}
		for _, endpoint := range inspection.Endpoints {
			order := "default"
			if endpoint.Order != nil {
				order = strconv.Itoa(int(*endpoint.Order))
			}
			chain.Endpoints = append(chain.Endpoints, views.ChainEndpointVM{
				Name: endpoint.Name, HTTPURL: endpoint.HTTPURL, WSURL: endpoint.WSURL, Order: order,
			})
		}
		attributes := append([]chainaccess.ChainAttribute(nil), inspection.Attributes...)
		sort.Slice(attributes, func(i, j int) bool { return attributes[i].Name < attributes[j].Name })
		for _, attribute := range attributes {
			chain.Attributes = append(chain.Attributes, views.ChainAttributeVM(attribute))
		}
		vm.Chains = append(vm.Chains, chain)
	}
	h.render(c, http.StatusOK, views.ChainConfigsPage(vm, h.navigation))
}

func chainDisplayName(selector protocol.ChainSelector) string {
	if name, err := chainsel.GetChainNameFromSelector(uint64(selector)); err == nil {
		return name
	}
	return selector.String()
}
