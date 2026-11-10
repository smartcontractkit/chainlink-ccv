package verifier

import (
	"fmt"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/pkg/chainaccess"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/token/cctp"
)

// tableCodec is a CCTPCodec that implements only Domain, backed by a family's base table.
// cctp.ValidateDomains calls only Domain, so the embedded interface's other methods stay nil.
type tableCodec struct {
	chainaccess.CCTPCodec
	table cctp.BaseDomainTable
}

func (c tableCodec) Domain(selector protocol.ChainSelector) (uint32, bool) {
	return c.table(selector)
}

// validateCCTPDomains checks each CCTP verifier_addresses chain whose family registered a base domain table.
// Other families and resolver-only chains are skipped: their codecs only exist at startup.
func validateCCTPDomains(cfg token.Config) error {
	for _, v := range cfg.TokenVerifiers {
		if !v.IsCCTP() {
			continue
		}
		scoped := *v.CCTPConfig
		scoped.ParsedVerifiers = make(map[protocol.ChainSelector]protocol.UnknownAddress)
		scoped.ParsedVerifierResolvers = nil
		codecs := make(map[protocol.ChainSelector]chainaccess.CCTPCodec)
		for selector, addr := range v.ParsedVerifiers {
			family, err := chainsel.GetSelectorFamily(uint64(selector))
			if err != nil {
				return fmt.Errorf("invalid CCTP verifier chain selector: %s: %w", selector, err)
			}
			if table, ok := cctp.BaseDomainTableFor(chainaccess.ChainFamily(family)); ok {
				scoped.ParsedVerifiers[selector] = addr
				codecs[selector] = tableCodec{table: table}
			}
		}
		if err := cctp.ValidateDomains(scoped, codecs); err != nil {
			return fmt.Errorf("invalid cctp verifier %q: %w", v.VerifierID, err)
		}
	}
	return nil
}
