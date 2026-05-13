package devenvruntime_test

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks "github.com/smartcontractkit/chainlink-ccv/build/devenv/internal/mocks"
	devenvruntime "github.com/smartcontractkit/chainlink-ccv/build/devenv/runtime"
)

func runEnv(t *testing.T, r *devenvruntime.Registry, rawConfig map[string]any) (map[string]any, error) {
	t.Helper()
	return devenvruntime.NewEnvironmentWithRegistry(context.Background(), rawConfig, r, zerolog.Nop())
}

func compFactory(c devenvruntime.Component) devenvruntime.ComponentFactory {
	return func(_ map[string]any) (devenvruntime.Component, error) { return c, nil }
}

// p1Comp implements Component + Phase1Component via embedded mocks.
type p1Comp struct {
	*mocks.MockComponent
	*mocks.MockPhase1Component
}

func newP1Comp(t *testing.T, output map[string]any) *p1Comp {
	t.Helper()
	c := mocks.NewMockComponent(t)
	c.EXPECT().ValidateConfig(mock.Anything).Return(nil)
	p := mocks.NewMockPhase1Component(t)
	p.EXPECT().RunPhase1(mock.Anything, mock.Anything, mock.Anything).Return(output, nil, nil)
	return &p1Comp{MockComponent: c, MockPhase1Component: p}
}

// p2Comp implements Component + Phase2Component. onCall (if non-nil) runs with
// the priorOutputs map handed to the component, before output is returned.
type p2Comp struct {
	*mocks.MockComponent
	*mocks.MockPhase2Component
}

func newP2Comp(t *testing.T, output map[string]any, onCall func(prior map[string]any)) *p2Comp {
	t.Helper()
	c := mocks.NewMockComponent(t)
	c.EXPECT().ValidateConfig(mock.Anything).Return(nil)
	p := mocks.NewMockPhase2Component(t)
	p.EXPECT().RunPhase2(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ map[string]any, _ any, prior map[string]any) (map[string]any, []devenvruntime.Effect, error) {
			if onCall != nil {
				onCall(prior)
			}
			return output, nil, nil
		})
	return &p2Comp{MockComponent: c, MockPhase2Component: p}
}

// p234Comp implements Component plus Phase2/3/4. Each phase callback captures
// its priorOutputs into the corresponding pointer (if non-nil) and returns no
// output.
type p234Comp struct {
	*mocks.MockComponent
	*mocks.MockPhase2Component
	*mocks.MockPhase3Component
	*mocks.MockPhase4Component
}

func newP234Capturer(t *testing.T, p2, p3, p4 *map[string]any) *p234Comp {
	t.Helper()
	c := mocks.NewMockComponent(t)
	c.EXPECT().ValidateConfig(mock.Anything).Return(nil)

	mp2 := mocks.NewMockPhase2Component(t)
	mp2.EXPECT().RunPhase2(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ map[string]any, _ any, prior map[string]any) (map[string]any, []devenvruntime.Effect, error) {
			if p2 != nil {
				*p2 = prior
			}
			return nil, nil, nil
		})

	mp3 := mocks.NewMockPhase3Component(t)
	mp3.EXPECT().RunPhase3(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ map[string]any, _ any, prior map[string]any) (map[string]any, []devenvruntime.Effect, error) {
			if p3 != nil {
				*p3 = prior
			}
			return nil, nil, nil
		})

	mp4 := mocks.NewMockPhase4Component(t)
	mp4.EXPECT().RunPhase4(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ map[string]any, _ any, prior map[string]any) (map[string]any, []devenvruntime.Effect, error) {
			if p4 != nil {
				*p4 = prior
			}
			return nil, nil, nil
		})

	return &p234Comp{
		MockComponent:       c,
		MockPhase2Component: mp2,
		MockPhase3Component: mp3,
		MockPhase4Component: mp4,
	}
}

func TestPhaseSnapshot_SiblingsCannotSeeEachOther(t *testing.T) {
	var alphaPrior, betaPrior map[string]any
	alpha := newP2Comp(t, map[string]any{"from-alpha": 1}, func(p map[string]any) { alphaPrior = p })
	beta := newP2Comp(t, map[string]any{"from-beta": 2}, func(p map[string]any) { betaPrior = p })

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("Alpha", compFactory(alpha)))
	require.NoError(t, r.Register("Beta", compFactory(beta)))

	out, err := runEnv(t, r, map[string]any{"Alpha": nil, "Beta": nil})
	require.NoError(t, err)

	require.NotContains(t, alphaPrior, "from-beta", "alpha must not see beta's output")
	require.NotContains(t, betaPrior, "from-alpha", "beta must not see alpha's output")

	require.Equal(t, 1, out["from-alpha"])
	require.Equal(t, 2, out["from-beta"])
}

func TestPhaseSnapshot_MutationByOneSiblingDoesNotLeak(t *testing.T) {
	producer := newP1Comp(t, map[string]any{"p1-out": "original"})

	mutator := newP2Comp(t, nil, func(prior map[string]any) {
		prior["injected-by-mutator"] = "boom"
		delete(prior, "p1-out")
	})

	var observerPrior map[string]any
	observer := newP2Comp(t, nil, func(p map[string]any) { observerPrior = p })

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("Producer", compFactory(producer)))
	// Sort order in phase 2: Mutator < Observer < Producer. Mutator runs first
	// and trashes its priorOutputs clone; Observer must still see the pristine
	// phase-start state.
	require.NoError(t, r.Register("Mutator", compFactory(mutator)))
	require.NoError(t, r.Register("Observer", compFactory(observer)))

	_, err := runEnv(t, r, map[string]any{"Producer": nil, "Mutator": nil, "Observer": nil})
	require.NoError(t, err)

	require.Equal(t, "original", observerPrior["p1-out"],
		"observer must still see the phase-start value despite mutator's delete")
	require.NotContains(t, observerPrior, "injected-by-mutator",
		"mutator's injection must not leak into observer's snapshot")
}

func TestPhaseSnapshot_NextPhaseSeesPriorPhaseOutputs(t *testing.T) {
	producer := newP1Comp(t, map[string]any{"p1-out": "hello"})

	var p2Prior, p3Prior, p4Prior map[string]any
	consumer := newP234Capturer(t, &p2Prior, &p3Prior, &p4Prior)

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("Producer", compFactory(producer)))
	require.NoError(t, r.Register("Consumer", compFactory(consumer)))

	_, err := runEnv(t, r, map[string]any{"Producer": nil, "Consumer": nil})
	require.NoError(t, err)

	require.Equal(t, "hello", p2Prior["p1-out"])
	require.Equal(t, "hello", p3Prior["p1-out"])
	require.Equal(t, "hello", p4Prior["p1-out"])
}

func TestMergeNoOverwrite_SamePhaseCollision(t *testing.T) {
	alpha := newP2Comp(t, map[string]any{"shared": 1}, nil)
	beta := newP2Comp(t, map[string]any{"shared": 2}, nil)

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("Alpha", compFactory(alpha)))
	require.NoError(t, r.Register("Beta", compFactory(beta)))

	_, err := runEnv(t, r, map[string]any{"Alpha": nil, "Beta": nil})
	require.Error(t, err)
	// Beta runs second under sortedKeys, so it's the one that detects the collision.
	require.Contains(t, err.Error(), "phase 2")
	require.Contains(t, err.Error(), `"Beta"`)
	require.Contains(t, err.Error(), `"shared"`)
}

func TestMergeNoOverwrite_PriorPhaseCollision(t *testing.T) {
	producer := newP1Comp(t, map[string]any{"shared": "p1"})
	overwriter := newP2Comp(t, map[string]any{"shared": "p2"}, nil)

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("Overwriter", compFactory(overwriter)))
	require.NoError(t, r.Register("Producer", compFactory(producer)))

	_, err := runEnv(t, r, map[string]any{"Overwriter": nil, "Producer": nil})
	require.Error(t, err)
	require.Contains(t, err.Error(), "phase 2")
	require.Contains(t, err.Error(), `"Overwriter"`)
	require.Contains(t, err.Error(), `"shared"`)
}

func TestMergeNoOverwrite_DistinctKeysSucceed(t *testing.T) {
	a := newP2Comp(t, map[string]any{"a-key": "a-val"}, nil)
	b := newP2Comp(t, map[string]any{"b-key": "b-val"}, nil)

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("A", compFactory(a)))
	require.NoError(t, r.Register("B", compFactory(b)))

	out, err := runEnv(t, r, map[string]any{"A": nil, "B": nil})
	require.NoError(t, err)
	require.Equal(t, "a-val", out["a-key"])
	require.Equal(t, "b-val", out["b-key"])
}

func TestPhase1_OverwriteDetection(t *testing.T) {
	a := newP1Comp(t, map[string]any{"shared": 1})
	b := newP1Comp(t, map[string]any{"shared": 2})

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("A", compFactory(a)))
	require.NoError(t, r.Register("B", compFactory(b)))

	_, err := runEnv(t, r, map[string]any{"A": nil, "B": nil})
	require.Error(t, err)
	require.Contains(t, err.Error(), "phase 1")
	require.Contains(t, err.Error(), `"B"`)
	require.Contains(t, err.Error(), `"shared"`)
}

func TestFallbackHonorsSnapshot(t *testing.T) {
	specific := newP2Comp(t, map[string]any{"from-specific": 1}, nil)

	var fallbackPrior map[string]any
	fb := newP2Comp(t, map[string]any{"from-fallback": 2}, func(p map[string]any) { fallbackPrior = p })

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("Specific", compFactory(specific)))
	r.SetFallback(compFactory(fb))

	out, err := runEnv(t, r, map[string]any{"Specific": nil, "Other": nil})
	require.NoError(t, err)

	require.NotContains(t, fallbackPrior, "from-specific",
		"fallback must see the phase-start snapshot, not the post-Specific state")
	require.Equal(t, 1, out["from-specific"])
	require.Equal(t, 2, out["from-fallback"])
}

func TestFallbackOverwriteDetection(t *testing.T) {
	specific := newP2Comp(t, map[string]any{"shared": "specific"}, nil)
	fb := newP2Comp(t, map[string]any{"shared": "fallback"}, nil)

	r := devenvruntime.NewRegistry()
	require.NoError(t, r.Register("Specific", compFactory(specific)))
	r.SetFallback(compFactory(fb))

	_, err := runEnv(t, r, map[string]any{"Specific": nil})
	require.Error(t, err)
	require.Contains(t, err.Error(), "phase 2")
	require.Contains(t, err.Error(), `"<fallback>"`)
	require.Contains(t, err.Error(), `"shared"`)
}
