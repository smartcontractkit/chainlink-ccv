package verifiercli

import (
	"context"
	"errors"
	"fmt"
)

// CommitteeClient groups the set of verifier Clients that share a
// VerifierID, i.e. members of the same signing committee. It exists so
// tests that simulate operational recovery (e.g. rewinding a chain
// checkpoint after a curse drop) can coordinate every member in
// lockstep: the aggregator only returns a result once every committee
// member has signed, so half-measures leave the message stuck.
type CommitteeClient struct {
	verifierID string
	members    []*Client
}

// NewCommitteeClient returns a CommitteeClient for verifierID with the
// given members. The caller is responsible for ensuring every member
// actually belongs to the named committee - typically by filtering
// `in.Verifier[].Out.VerifierID` at the test level.
//
// An empty members slice is rejected: no reasonable test can make
// progress without at least one member.
func NewCommitteeClient(verifierID string, members ...*Client) (*CommitteeClient, error) {
	if verifierID == "" {
		return nil, errors.New("verifiercli: committee verifier ID must not be empty")
	}
	if len(members) == 0 {
		return nil, errors.New("verifiercli: committee must have at least one member")
	}
	return &CommitteeClient{verifierID: verifierID, members: members}, nil
}

// VerifierID returns the committee's verifier ID.
func (c *CommitteeClient) VerifierID() string { return c.verifierID }

// Members returns the committee members in the order they were passed
// to NewCommitteeClient. The returned slice is the internal slice -
// callers must not mutate it.
func (c *CommitteeClient) Members() []*Client { return c.members }

// ResumeAllBestEffort sends pkill -CONT to every member, ignoring
// errors. Intended for t.Cleanup paths where we just want a healthy
// environment even if an earlier step failed mid-Pause.
func (c *CommitteeClient) ResumeAllBestEffort(ctx context.Context) {
	for _, m := range c.members {
		m.ResumeBestEffort(ctx)
	}
}

// RewindFinalizedHeight performs the full "CLI-driven replay" recovery
// sequence across all committee members:
//
//  1. Pause every member so its running verifier cannot race the CLI.
//  2. Overwrite each member's finalized-height checkpoint for
//     chainSelector.
//  3. Restart every member and wait for the CLI to be healthy again.
//
// Stopping and writing is done in one pass per member - keeping each
// member paused only for its own write shortens the window where the
// source chain has no committee coverage.
//
// On any error the function stops and returns, but every paused member
// is best-effort resumed before returning so the test environment is
// left runnable. Tests should still defer ResumeAllBestEffort in
// t.Cleanup as a belt-and-braces measure.
func (c *CommitteeClient) RewindFinalizedHeight(ctx context.Context, chainSelector ChainSelector, height BlockHeight) error {
	for _, m := range c.members {
		if err := m.Pause(ctx); err != nil {
			c.ResumeAllBestEffort(ctx)
			return fmt.Errorf("pause %s: %w", m.Container(), err)
		}
		if _, err := m.ChainStatuses().SetFinalizedHeight(ctx, chainSelector, c.verifierID, height); err != nil {
			c.ResumeAllBestEffort(ctx)
			return fmt.Errorf("set-finalized-height on %s: %w", m.Container(), err)
		}
	}
	// Restart is its own pass because a restart implicitly un-pauses
	// the process - we want all writes committed before any member
	// comes back online.
	for _, m := range c.members {
		if err := m.RestartAndWaitReady(ctx); err != nil {
			c.ResumeAllBestEffort(ctx)
			return fmt.Errorf("restart %s: %w", m.Container(), err)
		}
	}
	return nil
}
