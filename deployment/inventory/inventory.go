// Package inventory records who runs what in a CCV environment: operators (NOPs), their nodes and
// signing keys, committee membership and executor pools. It is chain-family agnostic: every family
// is covered through data CCV changesets already persist and the adapters families already register.
package inventory

import (
	"fmt"
	"strconv"
	"time"
)

// SchemaVersion changes whenever the JSON shape of Inventory changes incompatibly.
// Version 2 groups identical onchain committees across their verifier deployments.
const SchemaVersion = 2

// ChainSelector encodes as a decimal string in JSON: selectors exceed the integers JSON numbers
// carry exactly, and CCV env metadata already stores them as strings.
type ChainSelector uint64

func (s ChainSelector) MarshalText() ([]byte, error) {
	return strconv.AppendUint(nil, uint64(s), 10), nil
}

func (s *ChainSelector) UnmarshalText(text []byte) error {
	v, err := strconv.ParseUint(string(text), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chain selector %q: %w", text, err)
	}
	*s = ChainSelector(v)
	return nil
}

// Inventory holds normalized tables; ByNOP, ByChain and Rows derive the common slices from them.
type Inventory struct {
	SchemaVersion int              `json:"schemaVersion"`
	Chains        []Chain          `json:"chains"`
	NOPs          []NOP            `json:"nops"`
	Nodes         []Node           `json:"nodes"`
	Committees    []Committee      `json:"committees"`
	Verifiers     []Verifier       `json:"verifiers"`
	ExecutorPools []ExecutorPool   `json:"executorPools"`
	Refreshes     []OnchainRefresh `json:"onchainRefreshes,omitempty"`
	Issues        []Issue          `json:"issues,omitempty"`
}

// OnchainRefresh is the last scan outcome for one verifier chain. A failed attempt keeps the
// previous successful scan's committees: LastError then marks that retained data as stale,
// while an empty result from a successful scan means the committee was actually removed.
type OnchainRefresh struct {
	Chain         ChainSelector `json:"chainSelector"`
	LastSuccessAt time.Time     `json:"lastSuccessAt,omitzero"`
	LastAttemptAt time.Time     `json:"lastAttemptAt,omitzero"`
	LastError     string        `json:"lastError,omitempty"`
}

// Chain identifies a chain by selector, with its chain-selectors name and family.
type Chain struct {
	Selector ChainSelector `json:"selector"`
	Name     string        `json:"name,omitempty"`
	Family   string        `json:"family,omitempty"`
}

// NOP is an operator alias as CCV deployment tooling addresses it; one NOP may run several nodes.
type NOP struct {
	Alias   string           `json:"alias"`
	Mode    string           `json:"mode,omitempty"`
	Signers []SignerIdentity `json:"signers,omitempty"`
	NodeIDs []string         `json:"nodeIds,omitempty"`
}

// SignerIdentity is one family's form of a NOP's secp256k1 signing key. Address is the canonical
// address every form reduces to; it is empty when Value is neither a valid key nor an address.
type SignerIdentity struct {
	Family  string `json:"family"`
	Value   string `json:"value"`
	Address string `json:"address,omitempty"`
}

// Role is what a node does for CCV.
type Role string

const (
	RoleVerifier Role = "verifier"
	RoleExecutor Role = "executor"
)

// VerifierScope pairs one verifier job's committee qualifier with its source chains, keeping the
// two dimensions attached to the job. Qualifier is empty when no known qualifier matches.
// Proposal fields describe the last persisted JD sync, not live process health.
type VerifierScope struct {
	JobID                string          `json:"jobId"`
	JDJobID              string          `json:"jdJobId,omitempty"`
	HasActiveProposal    bool            `json:"hasActiveProposal"`
	ActiveProposalID     string          `json:"activeProposalId,omitempty"`
	LatestProposalStatus string          `json:"latestProposalStatus,omitempty"`
	Qualifier            string          `json:"qualifier,omitempty"`
	SourceChains         []ChainSelector `json:"sourceChains,omitempty"`
}

// Node is a Job Distributor node and the CCV roles it runs.
type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	CSAKey   string `json:"csaKey"`
	NOPAlias string `json:"nopAlias,omitempty"`
	Roles    []Role `json:"roles,omitempty"`
	// VerifierScopes are this node's verifier jobs' committee and source-chain scopes.
	VerifierScopes []VerifierScope   `json:"verifierScopes,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
}

// Where a committee's signer set was read from.
const (
	SourceAggregator = "aggregator"
	SourceOnchain    = "onchain"
)

// VerifierDeployment identifies one deployed CommitteeVerifier holding an onchain signer set.
type VerifierDeployment struct {
	Chain   ChainSelector `json:"chainSelector"`
	Address string        `json:"address"`
}

// Committee is one signer set and quorum for a source chain, from aggregator configs or onchain reads.
// Identical onchain sets share VerifierDeployments; different sets remain separate.
// Singular verifier fields hold schema-v1 snapshots and live scans.
type Committee struct {
	Source              string               `json:"source"`
	Aggregators         []string             `json:"aggregators,omitempty"`
	VerifierChain       ChainSelector        `json:"verifierChainSelector,omitempty"`
	VerifierAddress     string               `json:"verifierAddress,omitempty"`
	VerifierDeployments []VerifierDeployment `json:"verifierDeployments,omitempty"`
	Qualifier           string               `json:"qualifier,omitempty"`
	SourceChain         ChainSelector        `json:"sourceChainSelector"`
	SourceVerifier      string               `json:"sourceVerifierAddress,omitempty"`
	Threshold           uint8                `json:"threshold"`
	Members             []Member             `json:"members"`
}

// Member is one committee signer, resolved to its NOP and signing node when the data allows.
type Member struct {
	SignerAddress string `json:"signerAddress"`
	SignerPubKey  string `json:"signerPubKey,omitempty"`
	NOPAlias      string `json:"nopAlias,omitempty"`
	NodeID        string `json:"nodeId,omitempty"`
	CSAKey        string `json:"csaKey,omitempty"`
}

// Verifier is the CommitteeVerifier a destination chain uses to check one committee's signatures.
type Verifier struct {
	Chain       ChainSelector `json:"chainSelector"`
	Qualifier   string        `json:"qualifier,omitempty"`
	Address     string        `json:"address"`
	Aggregators []string      `json:"aggregators"`
}

// ExecutorPool lists the NOPs one executor pool configures to execute on one chain.
type ExecutorPool struct {
	Pool    string           `json:"pool"`
	Chain   ChainSelector    `json:"chainSelector"`
	Members []ExecutorMember `json:"members"`
}

// ExecutorMember is one configured executor. Unsupported marks a member whose node type cannot run
// this chain's family (CL nodes only run EVM chain blocks), so nothing actually executes there.
type ExecutorMember struct {
	NOPAlias    string `json:"nopAlias"`
	NodeID      string `json:"nodeId,omitempty"`
	CSAKey      string `json:"csaKey,omitempty"`
	Mode        string `json:"mode,omitempty"`
	Unsupported bool   `json:"unsupported,omitempty"`
}

// Issue kinds. An issue records data the builder could not reconcile; the rest is still usable.
const (
	IssueInvalidSigner            = "invalid-signer"
	IssueSignerMismatch           = "signer-mismatch"
	IssueAmbiguousSigner          = "ambiguous-signer"
	IssueUnresolvedSigner         = "unresolved-signer"
	IssueMissingNode              = "missing-node"
	IssueAmbiguousNode            = "ambiguous-node"
	IssueVerifierScopeConflict    = "verifier-scope-conflict"
	IssueAggregatorDrift          = "aggregator-drift"
	IssueExecutorPoolDrift        = "executor-pool-drift"
	IssueUnsupportedExecutorChain = "unsupported-executor-chain"
	IssueUnreadableJob            = "unreadable-job"
	IssueOnchainReadFailed        = "onchain-read-failed"
	IssueOnchainDrift             = "onchain-drift"
)

// Issue is one finding, keyed by kind and the thing it is about.
type Issue struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}
