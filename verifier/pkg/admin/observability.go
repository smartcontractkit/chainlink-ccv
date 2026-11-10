package admin

import (
	"context"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-ccv/verifier/pkg/admin/views"
)

// TransmitterKeyBalance is one public transmitter key and its native-token balance.
type TransmitterKeyBalance struct {
	KeyName  string
	Address  string
	Amount   *big.Int
	Decimals uint8
}

// ChainTransmitterBalances keeps a chain's lookup failure separate from successful key reads.
type ChainTransmitterBalances struct {
	ChainSelector protocol.ChainSelector
	Keys          []TransmitterKeyBalance
	Err           error
}

// TransmitterBalanceSource reads current balances when the admin page is requested.
type TransmitterBalanceSource interface {
	TransmitterBalances(ctx context.Context) []ChainTransmitterBalances
}

func (h *handlers) registerObservabilityRoutes(r *gin.Engine) {
	r.GET("/job", h.jobSpecPage)
	if h.balanceSource != nil {
		r.GET("/transmitter-keys", h.transmitterKeysPage)
	}
}

func (h *handlers) jobSpecPage(c *gin.Context) {
	vm := views.JobSpecVM{Available: h.jobSpec != nil}
	if h.jobSpec != nil {
		configField := h.jobSpec.ConfigFieldName
		if configField == "" {
			configField = "appConfig"
		}
		vm.Name = h.jobSpec.Name
		vm.ExternalJobID = h.jobSpec.ExternalJobID
		vm.SchemaVersion = h.jobSpec.SchemaVersion
		vm.Type = h.jobSpec.Type
		vm.ConfigFieldName = configField
		vm.AppConfig = h.jobSpec.AppConfig
	}
	h.render(c, http.StatusOK, views.JobSpecPage(vm, h.navigation))
}

func (h *handlers) transmitterKeysPage(c *gin.Context) {
	chains := h.balanceSource.TransmitterBalances(c.Request.Context())
	sort.Slice(chains, func(i, j int) bool { return chains[i].ChainSelector < chains[j].ChainSelector })
	vm := views.TransmitterKeysVM{RefreshedAt: time.Now().UTC(), Chains: make([]views.TransmitterChainVM, 0, len(chains))}
	for _, chain := range chains {
		chainVM := views.TransmitterChainVM{ChainSelector: chain.ChainSelector.String(), ChainName: chain.ChainSelector.String()}
		if name, err := chainsel.GetChainNameFromSelector(uint64(chain.ChainSelector)); err == nil {
			chainVM.ChainName = name
		}
		if chain.Err != nil {
			chainVM.Error = chain.Err.Error()
		}
		keys := append([]TransmitterKeyBalance(nil), chain.Keys...)
		sort.Slice(keys, func(i, j int) bool { return keys[i].Address < keys[j].Address })
		for _, key := range keys {
			keyVM := views.TransmitterKeyVM{KeyName: key.KeyName, Address: key.Address, Balance: "unavailable"}
			if key.Amount != nil {
				keyVM.Balance = formatNativeBalance(key.Amount, key.Decimals)
				keyVM.BaseUnits = key.Amount.String()
			}
			chainVM.Keys = append(chainVM.Keys, keyVM)
		}
		vm.Chains = append(vm.Chains, chainVM)
	}
	h.render(c, http.StatusOK, views.TransmitterKeysPage(vm, h.navigation))
}

func formatNativeBalance(amount *big.Int, decimals uint8) string {
	if amount == nil {
		return "unavailable"
	}
	if decimals == 0 {
		return amount.String()
	}
	negative := amount.Sign() < 0
	absolute := new(big.Int).Abs(new(big.Int).Set(amount))
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	whole, remainder := new(big.Int), new(big.Int)
	whole.QuoRem(absolute, scale, remainder)
	fraction := strings.Repeat("0", int(decimals)) + remainder.String()
	fraction = fraction[len(fraction)-int(decimals):]
	fraction = strings.TrimRight(fraction, "0")
	result := whole.String()
	if fraction != "" {
		result += "." + fraction
	}
	if negative {
		return "-" + result
	}
	return result
}

func jobSpecSnapshot(spec *bootstrap.JobSpec) *bootstrap.JobSpec {
	if spec == nil {
		return nil
	}
	snapshot := *spec
	return &snapshot
}
