package inventory

import (
	"encoding/csv"
	"io"
	"slices"
	"strconv"
	"strings"
)

// NOPView is everything about one NOP: its nodes and where it verifies and executes.
type NOPView struct {
	NOP
	Nodes       []Node          `json:"nodes"`
	VerifierFor []ChainSelector `json:"verifierForSourceChains"`
	ExecutorOn  []ChainSelector `json:"executorOnChains"`
}

// ByNOP keys a view of every NOP by alias. Verification comes from the aggregator committees.
func (inv *Inventory) ByNOP() map[string]NOPView {
	nodes := inv.nodeIndex()
	out := make(map[string]NOPView, len(inv.NOPs))
	for _, nop := range inv.NOPs {
		view := NOPView{NOP: nop, Nodes: []Node{}, VerifierFor: []ChainSelector{}, ExecutorOn: []ChainSelector{}}
		for _, id := range nop.NodeIDs {
			if node, ok := nodes[id]; ok {
				view.Nodes = append(view.Nodes, node)
			}
		}
		out[nop.Alias] = view
	}
	for _, c := range inv.Committees {
		if c.Source != SourceAggregator {
			continue
		}
		for _, m := range c.Members {
			if view, ok := out[m.NOPAlias]; ok && !slices.Contains(view.VerifierFor, c.SourceChain) {
				view.VerifierFor = append(view.VerifierFor, c.SourceChain)
				out[m.NOPAlias] = view
			}
		}
	}
	for _, p := range inv.ExecutorPools {
		for _, m := range p.Members {
			if view, ok := out[m.NOPAlias]; ok && !m.Unsupported && !slices.Contains(view.ExecutorOn, p.Chain) {
				view.ExecutorOn = append(view.ExecutorOn, p.Chain)
				out[m.NOPAlias] = view
			}
		}
	}
	for alias, view := range out {
		slices.Sort(view.VerifierFor)
		slices.Sort(view.ExecutorOn)
		out[alias] = view
	}
	return out
}

// ChainView is everything about one chain: the committees attesting its messages, the signer sets
// its own verifier holds, the verifier contract itself, and the executor pools configured on it.
type ChainView struct {
	Chain
	Committees         []Committee    `json:"committees"`
	VerifierSignerSets []Committee    `json:"verifierSignerSets"`
	Verifiers          []Verifier     `json:"verifiers"`
	ExecutorPools      []ExecutorPool `json:"executorPools"`
}

// ByChain keys a view of every chain the inventory mentions by selector.
func (inv *Inventory) ByChain() map[ChainSelector]ChainView {
	out := make(map[ChainSelector]ChainView, len(inv.Chains))
	for _, chain := range inv.Chains {
		out[chain.Selector] = ChainView{
			Chain: chain, Committees: []Committee{}, VerifierSignerSets: []Committee{},
			Verifiers: []Verifier{}, ExecutorPools: []ExecutorPool{},
		}
	}
	update := func(sel ChainSelector, fn func(*ChainView)) {
		if view, ok := out[sel]; ok {
			fn(&view)
			out[sel] = view
		}
	}
	for _, c := range inv.Committees {
		update(c.SourceChain, func(v *ChainView) { v.Committees = append(v.Committees, c) })
		if c.Source == SourceOnchain {
			update(c.VerifierChain, func(v *ChainView) { v.VerifierSignerSets = append(v.VerifierSignerSets, c) })
		}
	}
	for _, v := range inv.Verifiers {
		update(v.Chain, func(view *ChainView) { view.Verifiers = append(view.Verifiers, v) })
	}
	for _, p := range inv.ExecutorPools {
		update(p.Chain, func(v *ChainView) { v.ExecutorPools = append(v.ExecutorPools, p) })
	}
	return out
}

// Row is one participation fact (a committee signer or a configured executor), flat for CSV and
// dashboards. Scope is the committee qualifier or executor pool; Chain is the source chain for
// verifiers and the execution chain for executors.
type Row struct {
	Role          Role          `json:"role"`
	Source        string        `json:"source"`
	Scope         string        `json:"scope"`
	Aggregators   string        `json:"aggregators,omitempty"`
	Chain         ChainSelector `json:"chainSelector"`
	ChainName     string        `json:"chainName"`
	ChainFamily   string        `json:"chainFamily"`
	VerifierChain ChainSelector `json:"verifierChainSelector,omitempty"`
	Threshold     uint8         `json:"threshold,omitempty"`
	NOPAlias      string        `json:"nopAlias"`
	NodeID        string        `json:"nodeId"`
	NodeName      string        `json:"nodeName"`
	CSAKey        string        `json:"csaKey"`
	SignerAddress string        `json:"signerAddress,omitempty"`
	SignerPubKey  string        `json:"signerPubKey,omitempty"`
	Unsupported   bool          `json:"unsupported,omitempty"`
}

// Rows flattens every committee member and executor pool member into one row each.
func (inv *Inventory) Rows() []Row {
	chains := make(map[ChainSelector]Chain, len(inv.Chains))
	for _, c := range inv.Chains {
		chains[c.Selector] = c
	}
	nodes := inv.nodeIndex()
	var rows []Row
	for _, c := range inv.Committees {
		for _, m := range c.Members {
			rows = append(rows, Row{
				Role: RoleVerifier, Source: c.Source, Scope: c.Qualifier, Aggregators: strings.Join(c.Aggregators, ","),
				Chain: c.SourceChain, ChainName: chains[c.SourceChain].Name, ChainFamily: chains[c.SourceChain].Family,
				VerifierChain: c.VerifierChain, Threshold: c.Threshold,
				NOPAlias: m.NOPAlias, NodeID: m.NodeID, NodeName: nodes[m.NodeID].Name, CSAKey: m.CSAKey,
				SignerAddress: m.SignerAddress, SignerPubKey: m.SignerPubKey,
			})
		}
	}
	for _, p := range inv.ExecutorPools {
		for _, m := range p.Members {
			rows = append(rows, Row{
				Role: RoleExecutor, Source: "job", Scope: p.Pool,
				Chain: p.Chain, ChainName: chains[p.Chain].Name, ChainFamily: chains[p.Chain].Family,
				NOPAlias: m.NOPAlias, NodeID: m.NodeID, NodeName: nodes[m.NodeID].Name, CSAKey: m.CSAKey,
				Unsupported: m.Unsupported,
			})
		}
	}
	return rows
}

var csvHeader = []string{
	"role", "source", "scope", "aggregators", "chain_selector", "chain_name", "chain_family", "verifier_chain_selector",
	"threshold", "nop_alias", "node_id", "node_name", "csa_key", "signer_address", "signer_pubkey", "unsupported",
}

// WriteCSV writes rows with a header line.
func WriteCSV(w io.Writer, rows []Row) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range rows {
		verifierChain, threshold := "", ""
		if r.VerifierChain != 0 {
			verifierChain = strconv.FormatUint(uint64(r.VerifierChain), 10)
		}
		if r.Role == RoleVerifier {
			threshold = strconv.FormatUint(uint64(r.Threshold), 10)
		}
		if err := cw.Write([]string{
			string(r.Role), r.Source, r.Scope, r.Aggregators, strconv.FormatUint(uint64(r.Chain), 10), r.ChainName, r.ChainFamily, verifierChain,
			threshold, r.NOPAlias, r.NodeID, r.NodeName, r.CSAKey, r.SignerAddress, r.SignerPubKey, strconv.FormatBool(r.Unsupported),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func (inv *Inventory) nodeIndex() map[string]Node {
	out := make(map[string]Node, len(inv.Nodes))
	for _, n := range inv.Nodes {
		out[n.ID] = n
	}
	return out
}
