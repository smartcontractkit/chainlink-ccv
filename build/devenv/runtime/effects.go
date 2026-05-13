package devenvruntime

import "math/big"

// Effect is a cross-cutting side-effect request returned by a component's
// RunPhaseN method. The runtime collects effects from all components in a
// phase and executes them (in a fixed order) before advancing to the next
// phase, using shared infrastructure (chain impls, JD client, CL node clients)
// that individual components should not own directly.
//
// Current ordering within a phase:
//  1. CLNodeConfigEffect — inject secrets before job proposals land
//  2. FundingEffect — fund addresses before they transact
//  3. JobProposalEffect — propose job specs to JD
type Effect interface{ effectMarker() }

// FundingEffect requests that Address be funded on ChainSelector.
// The runtime satisfies this by calling impl.FundAddresses on the chain
// implementation that holds the prefunded Anvil/deployer keys.
type FundingEffect struct {
	ChainSelector uint64
	Address       string
	NativeAmount  *big.Int
	LinkAmount    *big.Int // zero if not required
}

// JobProposalEffect requests that JobSpec be proposed to the node identified
// by NOPAlias via the Job Distributor. JobSpec must be fully-rendered TOML
// (blockchain_infos injected, etc.) before this effect is returned.
type JobProposalEffect struct {
	NOPAlias string
	JobSpec  string
}

// CLNodeConfigEffect requests that Secrets be applied to the CL node
// identified by NOPAlias before any JobProposalEffects are processed.
// Use this to inject aggregator HMAC credentials and similar runtime secrets
// that CommitteeCCV holds but the CL node needs before it can accept a job.
type CLNodeConfigEffect struct {
	NOPAlias string
	Secrets  map[string]string
}

func (FundingEffect) effectMarker()      {}
func (JobProposalEffect) effectMarker()  {}
func (CLNodeConfigEffect) effectMarker() {}
