package vtypes

import (
	"errors"
	"fmt"
)

// VerifierDecorator wraps a Verifier with an additional behavior — a gate, an accounting layer —
// and returns the wrapped verifier. A decorator is typically the result of a package-level factory
// that captures its own configuration (for example policy.Gate), so the construction site only
// ever sees this one shape. A decorator that decides it has nothing to add returns its argument
// unchanged, which leaves no extra layer in the call path.
type VerifierDecorator func(inner Verifier) (Verifier, error)

// Chain applies decorators to inner and returns the outermost verifier. The first decorator
// listed is the outermost: it sees every task first and decides what the rest of the chain sees.
// A nil decorator is skipped, so a factory may return nil for "not configured" instead of a
// pass-through.
//
// Chain exists so that adding a second gate is appending one entry at the construction site
// rather than writing a second bespoke wrapper around Verifier.
func Chain(inner Verifier, decorators ...VerifierDecorator) (Verifier, error) {
	if inner == nil {
		return nil, errors.New("inner verifier is required")
	}

	wrapped := inner
	// Apply in reverse: the last decorator wraps inner, the first wraps everything after it.
	for i := len(decorators) - 1; i >= 0; i-- {
		if decorators[i] == nil {
			continue
		}
		v, err := decorators[i](wrapped)
		if err != nil {
			return nil, fmt.Errorf("verifier decorator %d: %w", i, err)
		}
		if v == nil {
			return nil, fmt.Errorf("verifier decorator %d returned nil", i)
		}
		wrapped = v
	}
	return wrapped, nil
}
