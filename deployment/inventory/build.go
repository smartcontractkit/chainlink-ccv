package inventory

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/aggregator/pkg/model"
	"github.com/smartcontractkit/chainlink-ccv/deployment/shared"
)

// Inputs are the records CCV changesets persist that the inventory is derived from.
type Inputs struct {
	Aggregators          map[string]*model.Committee  // aggregator service -> config
	AggregatorQualifiers map[string]string            // aggregator service -> committee qualifier
	Signers              map[string]map[string]string // NOP alias -> chain family -> signer
	Nodes                map[string]NodeRecord        // JD node ID -> node
	Jobs                 shared.NOPJobs
}

// NodeRecord is the persisted Job Distributor view of one node.
type NodeRecord struct {
	Name   string
	CSAKey string
	Labels map[string]string
}

// Empty reports whether there is nothing to build an inventory from.
func (in Inputs) Empty() bool {
	return len(in.Aggregators) == 0 && len(in.Signers) == 0 && len(in.Nodes) == 0 && len(in.Jobs) == 0
}

// Build derives the inventory from persisted records. It reads nothing live and never fails:
// data it cannot reconcile becomes an Issue.
func Build(in Inputs) *Inventory {
	b := builderFor(&Inventory{SchemaVersion: SchemaVersion})
	b.addNOPs(in.Signers, in.Jobs)
	b.addNodes(in.Nodes, in.Jobs)
	r := buildResolver(b.inv.NOPs, b.inv.Nodes)
	b.reportAmbiguousSigners(r)
	b.addCommittees(in.Aggregators, in.AggregatorQualifiers, r)
	b.addExecutorPools(in.Jobs, r)
	b.reportIdentityGaps()
	b.inv.normalize()
	return b.inv
}

type builder struct {
	inv        *Inventory
	unresolved map[string]map[uint64]struct{} // signer address -> source chains whose committees use it
	nodeless   map[string]struct{}            // NOP aliases with a committee signer but no node
}

func builderFor(inv *Inventory) *builder {
	return &builder{inv: inv, unresolved: make(map[string]map[uint64]struct{}), nodeless: make(map[string]struct{})}
}

func (b *builder) issue(kind, subject, detail string) {
	b.inv.Issues = append(b.inv.Issues, Issue{Kind: kind, Subject: subject, Detail: detail})
}

func (b *builder) addNOPs(signers map[string]map[string]string, jobs shared.NOPJobs) {
	aliases := make(map[string]struct{}, len(signers)+len(jobs))
	modes := make(map[string]string)
	for alias := range signers {
		aliases[alias] = struct{}{}
	}
	for alias, byID := range jobs {
		aliases[string(alias)] = struct{}{}
		for _, id := range sortedKeys(byID) {
			if mode := string(byID[id].Mode); mode != "" && modes[string(alias)] == "" {
				modes[string(alias)] = mode
			}
		}
	}
	for _, alias := range sortedKeys(aliases) {
		nop := NOP{Alias: alias, Mode: modes[alias]}
		addresses := make(map[string]struct{})
		for _, family := range sortedKeys(signers[alias]) {
			id := SignerIdentity{Family: family, Value: signers[alias][family]}
			id.Address = canonicalSigner(family, id.Value)
			nop.Signers = append(nop.Signers, id)
			if id.Address == "" {
				b.issue(IssueInvalidSigner, alias,
					fmt.Sprintf("%s signer %q is neither a 20-byte address nor a 65-byte secp256k1 key", family, id.Value))
				continue
			}
			addresses[id.Address] = struct{}{}
		}
		if len(addresses) > 1 {
			b.issue(IssueSignerMismatch, alias, "signers reduce to different addresses: "+strings.Join(sortedKeys(addresses), ", "))
		}
		b.inv.NOPs = append(b.inv.NOPs, nop)
	}
}

func (b *builder) addNodes(jdNodes map[string]NodeRecord, jobs shared.NOPJobs) {
	nodeAlias := make(map[string]string)
	nodeRoles := make(map[string]map[Role]struct{})
	for _, alias := range sortedKeys(jobs) {
		for _, jobID := range sortedKeys(jobs[alias]) {
			job := jobs[alias][jobID]
			if job.NodeID == "" {
				continue
			}
			if _, ok := nodeAlias[job.NodeID]; !ok {
				nodeAlias[job.NodeID] = string(alias)
			}
			role, err := jobRole(job.Spec)
			if err != nil {
				b.issue(IssueUnreadableJob, string(jobID), err.Error())
				continue
			}
			if role != "" {
				if nodeRoles[job.NodeID] == nil {
					nodeRoles[job.NodeID] = make(map[Role]struct{})
				}
				nodeRoles[job.NodeID][role] = struct{}{}
			}
		}
	}

	aliasByLowerName := make(map[string]string, len(b.inv.NOPs))
	nopIndex := make(map[string]int, len(b.inv.NOPs))
	for i, nop := range b.inv.NOPs {
		aliasByLowerName[strings.ToLower(nop.Alias)] = nop.Alias
		nopIndex[nop.Alias] = i
	}
	for _, id := range sortedKeys(jdNodes) {
		jdNode := jdNodes[id]
		node := Node{ID: id, Name: jdNode.Name, CSAKey: jdNode.CSAKey, Labels: maps.Clone(jdNode.Labels)}
		// A job pins its node to a NOP; otherwise CCV tooling matches the node name to the alias.
		node.NOPAlias = nodeAlias[id]
		if node.NOPAlias == "" {
			node.NOPAlias = aliasByLowerName[strings.ToLower(jdNode.Name)]
		}
		node.Roles = sortedKeys(nodeRoles[id])
		if i, ok := nopIndex[node.NOPAlias]; ok {
			b.inv.NOPs[i].NodeIDs = append(b.inv.NOPs[i].NodeIDs, id)
		}
		b.inv.Nodes = append(b.inv.Nodes, node)
	}
}

func jobRole(spec string) (Role, error) {
	jobType, err := shared.JobSpecType(spec)
	if err != nil {
		return "", err
	}
	switch jobType {
	case shared.VerifierJobType:
		return RoleVerifier, nil
	case shared.ExecutorJobType:
		return RoleExecutor, nil
	default:
		return "", nil
	}
}

func (b *builder) reportAmbiguousSigners(r *resolver) {
	for _, addr := range sortedKeys(r.aliases) {
		if aliases := r.aliases[addr]; len(aliases) > 1 {
			b.issue(IssueAmbiguousSigner, addr, "claimed by "+strings.Join(aliases, ", "))
		}
	}
}

// committeeKey scopes aggregator data to one chain and committee; aggregators serving the same
// committee must agree on it, different committees may differ.
type committeeKey struct {
	chain     uint64
	qualifier string
}

func (k committeeKey) label() string {
	if k.qualifier == "" {
		return chainLabel(k.chain)
	}
	return fmt.Sprintf("%s (%s)", chainLabel(k.chain), k.qualifier)
}

func compareCommitteeKeys(a, b committeeKey) int {
	return cmp.Or(cmp.Compare(a.chain, b.chain), cmp.Compare(a.qualifier, b.qualifier))
}

func (b *builder) addCommittees(aggregators map[string]*model.Committee, qualifiers map[string]string, r *resolver) {
	sets := make(map[committeeKey][]Committee)              // distinct signer sets per source chain
	verifiers := make(map[committeeKey]map[string][]string) // destination verifier -> aggregators
	for _, name := range sortedKeys(aggregators) {
		cfg := aggregators[name]
		if cfg == nil {
			continue
		}
		qualifier := qualifiers[name]
		for _, key := range sortedKeys(cfg.QuorumConfigs) {
			source, err := strconv.ParseUint(key, 10, 64)
			qc := cfg.QuorumConfigs[key]
			if err != nil || qc == nil {
				continue
			}
			c := Committee{
				Source: SourceAggregator, Qualifier: qualifier, SourceChain: ChainSelector(source),
				SourceVerifier: qc.SourceVerifierAddress, Threshold: qc.Threshold,
			}
			c.Members = b.members(r, familyOf(source), signerValues(qc.Signers), source)
			k := committeeKey{source, qualifier}
			sets[k] = mergeCommittee(sets[k], c, name)
		}
		for _, key := range sortedKeys(cfg.DestinationVerifiers) {
			chain, err := strconv.ParseUint(key, 10, 64)
			if err != nil {
				continue
			}
			k := committeeKey{chain, qualifier}
			if verifiers[k] == nil {
				verifiers[k] = make(map[string][]string)
			}
			addr := cfg.DestinationVerifiers[key]
			verifiers[k][addr] = append(verifiers[k][addr], name)
		}
	}
	for _, k := range slices.SortedFunc(maps.Keys(sets), compareCommitteeKeys) {
		if len(sets[k]) > 1 {
			b.issue(IssueAggregatorDrift, k.label(),
				fmt.Sprintf("aggregators hold %d different signer sets for this source", len(sets[k])))
		}
		b.inv.Committees = append(b.inv.Committees, sets[k]...)
	}
	for _, k := range slices.SortedFunc(maps.Keys(verifiers), compareCommitteeKeys) {
		if len(verifiers[k]) > 1 {
			b.issue(IssueAggregatorDrift, k.label(),
				fmt.Sprintf("aggregators list %d different verifier contracts for this destination", len(verifiers[k])))
		}
		for _, addr := range sortedKeys(verifiers[k]) {
			b.inv.Verifiers = append(b.inv.Verifiers, Verifier{
				Chain: ChainSelector(k.chain), Qualifier: k.qualifier, Address: addr, Aggregators: verifiers[k][addr],
			})
		}
	}
}

// members resolves signers as family stores them, marks signing nodes as verifiers, and records
// signers no NOP claims or whose NOP has no node.
func (b *builder) members(r *resolver, family string, signers []string, source uint64) []Member {
	out := make([]Member, 0, len(signers))
	for _, signer := range signers {
		m := r.member(family, signer)
		switch node := r.verifierNode[m.NOPAlias]; {
		case m.NOPAlias == "" && len(r.aliases[m.SignerAddress]) > 1:
			// Already reported as an ambiguous signer.
		case m.NOPAlias == "":
			if b.unresolved[m.SignerAddress] == nil {
				b.unresolved[m.SignerAddress] = make(map[uint64]struct{})
			}
			b.unresolved[m.SignerAddress][source] = struct{}{}
		case node == nil:
			b.nodeless[m.NOPAlias] = struct{}{}
		case !slices.Contains(node.Roles, RoleVerifier):
			node.Roles = append(node.Roles, RoleVerifier)
		}
		out = append(out, m)
	}
	slices.SortFunc(out, func(x, y Member) int { return cmp.Compare(x.SignerAddress, y.SignerAddress) })
	return out
}

func (b *builder) reportIdentityGaps() {
	for _, addr := range sortedKeys(b.unresolved) {
		b.issue(IssueUnresolvedSigner, addr, "no NOP signer matches it; used for "+chainLabels(sortedKeys(b.unresolved[addr])))
	}
	for _, alias := range sortedKeys(b.nodeless) {
		b.issue(IssueMissingNode, alias, "committee signer has no node in jdNodes")
	}
	clear(b.unresolved)
	clear(b.nodeless)
}

// mergeCommittee records aggregator against an identical set already seen for the source, or adds c.
func mergeCommittee(sets []Committee, c Committee, aggregator string) []Committee {
	for i := range sets {
		if sameSignerSet(sets[i], c) && strings.EqualFold(sets[i].SourceVerifier, c.SourceVerifier) {
			sets[i].Aggregators = append(sets[i].Aggregators, aggregator)
			return sets
		}
	}
	c.Aggregators = []string{aggregator}
	return append(sets, c)
}

func sameSignerSet(a, b Committee) bool {
	return a.Threshold == b.Threshold && slices.Equal(memberAddresses(a.Members), memberAddresses(b.Members))
}

func memberAddresses(members []Member) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.SignerAddress)
	}
	slices.Sort(out)
	return out
}

func signerValues(signers []model.Signer) []string {
	out := make([]string, 0, len(signers))
	for _, s := range signers {
		out = append(out, s.Address)
	}
	return out
}

func (b *builder) addExecutorPools(jobs shared.NOPJobs, r *resolver) {
	type poolConfig struct {
		chains  map[uint64][]string // chain -> configured NOP aliases
		fromJob string
	}
	pools := make(map[string]*poolConfig)
	poolNodes := make(map[string]map[string]string)
	modes := make(map[string]string)
	for _, alias := range sortedKeys(jobs) {
		for _, jobID := range sortedKeys(jobs[alias]) {
			job := jobs[alias][jobID]
			if role, err := jobRole(job.Spec); err != nil || role != RoleExecutor {
				continue
			}
			cfg, err := shared.ParseExecutorJobSpec(job.Spec)
			if err != nil {
				b.issue(IssueUnreadableJob, string(jobID), err.Error())
				continue
			}
			chains := make(map[uint64][]string, len(cfg.ChainConfiguration))
			for key, cc := range cfg.ChainConfiguration {
				if chain, err := strconv.ParseUint(key, 10, 64); err == nil {
					chains[chain] = slices.Sorted(slices.Values(cc.ExecutorPool))
				}
			}
			if job.Mode != "" {
				modes[string(alias)] = string(job.Mode)
			}
			pool := executorPoolName(string(alias), string(jobID))
			if job.NodeID != "" {
				if poolNodes[pool] == nil {
					poolNodes[pool] = make(map[string]string)
				}
				poolNodes[pool][string(alias)] = job.NodeID
			}
			if existing, ok := pools[pool]; !ok {
				pools[pool] = &poolConfig{chains: chains, fromJob: string(jobID)}
			} else if !maps.EqualFunc(existing.chains, chains, slices.Equal[[]string]) {
				b.issue(IssueExecutorPoolDrift, pool, fmt.Sprintf("job %s configures different members than %s", jobID, existing.fromJob))
			}
		}
	}
	nodes := b.inv.nodeIndex()
	for _, pool := range sortedKeys(pools) {
		for _, chain := range sortedKeys(pools[pool].chains) {
			ep := ExecutorPool{Pool: pool, Chain: ChainSelector(chain)}
			family := familyOf(chain)
			var unsupported []string
			for _, alias := range pools[pool].chains[chain] {
				m := ExecutorMember{NOPAlias: alias, Mode: modes[alias]}
				if nodeID := poolNodes[pool][alias]; nodeID != "" {
					m.NodeID = nodeID
					m.CSAKey = nodes[nodeID].CSAKey
				} else if node := r.executorNode[alias]; node != nil {
					m.NodeID, m.CSAKey = node.ID, node.CSAKey
				}
				if m.Mode == string(shared.NOPModeCL) && family != "" && family != chainsel.FamilyEVM {
					m.Unsupported = true
					unsupported = append(unsupported, alias)
				}
				ep.Members = append(ep.Members, m)
			}
			if len(unsupported) > 0 {
				b.issue(IssueUnsupportedExecutorChain, chainLabel(chain), fmt.Sprintf(
					"pool %s configures %d CL-mode NOPs here, but CL nodes only run EVM chain blocks: %s",
					pool, len(unsupported), strings.Join(unsupported, ", "),
				))
			}
			b.inv.ExecutorPools = append(b.inv.ExecutorPools, ep)
		}
	}
}

// executorPoolName extracts the pool qualifier from an executor job ID ("<alias>-<pool>-executor").
func executorPoolName(alias, jobID string) string {
	rest, ok := strings.CutPrefix(jobID, alias+"-")
	if !ok {
		return jobID
	}
	if pool, ok := strings.CutSuffix(rest, "-executor"); ok && pool != "" {
		return pool
	}
	return jobID
}

// normalize derives the chain table and sorts every table so the output is stable.
func (inv *Inventory) normalize() {
	selectors := make(map[ChainSelector]struct{})
	for _, c := range inv.Committees {
		selectors[c.SourceChain] = struct{}{}
		if c.VerifierChain != 0 {
			selectors[c.VerifierChain] = struct{}{}
		}
	}
	for _, v := range inv.Verifiers {
		selectors[v.Chain] = struct{}{}
	}
	for _, p := range inv.ExecutorPools {
		selectors[p.Chain] = struct{}{}
	}
	inv.Chains = inv.Chains[:0]
	for _, sel := range sortedKeys(selectors) {
		inv.Chains = append(inv.Chains, Chain{Selector: sel, Name: chainName(uint64(sel)), Family: familyOf(uint64(sel))})
	}
	for i := range inv.Nodes {
		slices.Sort(inv.Nodes[i].Roles)
		inv.Nodes[i].Roles = slices.Compact(inv.Nodes[i].Roles)
	}
	slices.SortStableFunc(inv.Committees, func(a, b Committee) int {
		return cmp.Or(
			cmp.Compare(a.SourceChain, b.SourceChain),
			cmp.Compare(a.Source, b.Source),
			cmp.Compare(a.VerifierChain, b.VerifierChain),
			cmp.Compare(a.Qualifier, b.Qualifier),
			cmp.Compare(strings.Join(a.Aggregators, ","), strings.Join(b.Aggregators, ",")),
		)
	})
	slices.SortFunc(inv.Issues, func(a, b Issue) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Subject, b.Subject), cmp.Compare(a.Detail, b.Detail))
	})
	inv.Issues = slices.Compact(inv.Issues)
}

func familyOf(selector uint64) string {
	family, err := chainsel.GetSelectorFamily(selector)
	if err != nil {
		return ""
	}
	return family
}

func chainName(selector uint64) string {
	name, err := chainsel.GetChainNameFromSelector(selector)
	if err != nil {
		return ""
	}
	return name
}

func chainLabel(selector uint64) string {
	if name := chainName(selector); name != "" {
		return name
	}
	return strconv.FormatUint(selector, 10)
}

// chainLabels names up to five chains and counts the rest.
func chainLabels(selectors []uint64) string {
	const shown = 5
	labels := make([]string, 0, min(len(selectors), shown))
	for _, sel := range selectors[:min(len(selectors), shown)] {
		labels = append(labels, chainLabel(sel))
	}
	if extra := len(selectors) - shown; extra > 0 {
		return fmt.Sprintf("%s and %d more", strings.Join(labels, ", "), extra)
	}
	return strings.Join(labels, ", ")
}

func sortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	return slices.Sorted(maps.Keys(m))
}
