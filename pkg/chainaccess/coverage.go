package chainaccess

import (
	"errors"
	"fmt"
	"sync"
)

// DeclaredChainCoverageChecker validates, at process boot, that the chains an operator declares in
// the bootstrap config's [[chains]] are servable by the chain family's own mounted config. The
// declaration is the operator's statement of the chains they run — it is what registers their
// signing key in JD — so a chain named there that the family's config cannot serve is a config
// mistake that should fail the boot, not surface when the first message for the chain arrives.
//
// Families opt in by registering a checker next to their accessor factory (in the same init), which
// is also what keeps family specifics out of the shared bootstrap path: bootstrap only groups the
// declared chains by family and calls CheckDeclaredChainCoverage; how a family loads and judges its
// own config is the checker's business. A family without a registered checker has no family-local
// config contract to enforce and is skipped.
type DeclaredChainCoverageChecker func(chainIDs []string) error

var (
	declaredChainCoverageCheckers      = make(map[ChainFamily]DeclaredChainCoverageChecker)
	declaredChainCoverageCheckersMutex sync.RWMutex
)

// RegisterDeclaredChainCoverageChecker registers a family's coverage checker. Like Register, it is
// called from init and panics on a duplicate registration — that is a programmer error, not an
// operator one.
func RegisterDeclaredChainCoverageChecker(family ChainFamily, checker DeclaredChainCoverageChecker) {
	declaredChainCoverageCheckersMutex.Lock()
	defer declaredChainCoverageCheckersMutex.Unlock()

	if _, ok := declaredChainCoverageCheckers[family]; ok {
		panic(fmt.Sprintf("declared-chain coverage checker with name %s already exists", family))
	}
	declaredChainCoverageCheckers[family] = checker
}

// CheckDeclaredChainCoverage runs each family's registered checker over the chain IDs declared for
// that family (keyed by lower-cased family name, the same key space Register uses). Families with
// no registered checker are skipped. Every family's failure is returned, joined, so one boot log
// names all of them.
func CheckDeclaredChainCoverage(declaredByFamily map[ChainFamily][]string) error {
	declaredChainCoverageCheckersMutex.RLock()
	defer declaredChainCoverageCheckersMutex.RUnlock()

	var errs []error
	for family, chainIDs := range declaredByFamily {
		checker, ok := declaredChainCoverageCheckers[family]
		if !ok || len(chainIDs) == 0 {
			continue
		}
		if err := checker(chainIDs); err != nil {
			errs = append(errs, fmt.Errorf("family %s: %w", family, err))
		}
	}
	return errors.Join(errs...)
}
