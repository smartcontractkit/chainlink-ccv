package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/common"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/tests/e2e/tcapi/token_transfer"
	ccvchangesets "github.com/smartcontractkit/chainlink-ccv/deployment/changesets"

	// Register the EVM CCV adapters (incl. the token pool onchain adapter) so the
	// chain-agnostic RemoveRemotePool changeset can dispatch by family.
	_ "github.com/smartcontractkit/chainlink-ccv/integration/evm/adapters"
)

// TestE2ESmoke_RemoveRemotePool proves RemoveRemotePool has the intended effect,
// chain-agnostically, by driving real token transfers:
//
//  1. token expansion has configured a token for transfer between two chains (done
//     at env bootstrap), and we confirm a src->dest transfer succeeds;
//  2. RemoveRemotePool removes src's pool from the *dest* pool (dest validates the
//     source pool on releaseOrMint, so this is the entry that authorizes src->dest);
//  3. the same transfer now fails.
//
// The remote pool is identified by the remote token — the remote chain's adapter
// resolves its own pool address (PDA-safe for families like Solana), so nothing in
// this test is EVM-specific beyond the env it runs against.
//
// Requires a running devenv (same as the other smoke tests).
func TestE2ESmoke_RemoveRemotePool(t *testing.T) {
	ctx := ccv.Plog.WithContext(t.Context())

	lib, err := ccv.NewLibFromCCVEnv(&ccv.Plog, GetSmokeTestConfig())
	require.NoError(t, err)

	env, err := lib.CLDFEnvironment()
	require.NoError(t, err)

	chains, err := lib.Chains(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chains), 2, "expected at least 2 chains for this test in the environment")

	src := chains[0].CCIP17.ChainSelector()
	dest := chains[1].CCIP17.ChainSelector()

	// Find a token combo whose src->dest transfer prerequisites are satisfied.
	var combo common.TokenCombination
	var found bool
	for _, c := range common.AllTokenCombinations() {
		tc := token_transfer.TokenTransfer(lib, src, dest, c, c.FinalityConfig(), true, "remove-remote-pool precheck", token_transfer.Args{})
		if tc.HavePrerequisites(ctx) {
			combo = c
			found = true
			break
		}
	}
	if !found {
		t.Skip("no token combination with satisfied transfer prerequisites between the first two chains")
	}

	// 1. Transfer works before removal.
	pre := token_transfer.TokenTransfer(lib, src, dest, combo, combo.FinalityConfig(), true, "remove-remote-pool before", token_transfer.Args{})
	require.NoError(t, pre.Run(ctx), "token transfer should succeed before the remote pool is removed")

	// Resolve the token addresses on each side (family-native strings) the same way
	// the transfer test cases do, via each chain's registered address resolver.
	srcToken, destToken := resolveComboTokens(t, lib, src, dest, combo)

	// 2. Remove src's pool from the DEST pool, breaking src->dest.
	_, err = ccvchangesets.RemoveRemotePool().Apply(*env, ccvchangesets.RemoveRemotePoolInput{
		ChainSelector:       dest,
		TokenAddress:        destToken,
		RemoteChainSelector: src,
		RemoteTokenAddress:  srcToken,
	})
	require.NoError(t, err, "RemoveRemotePool should succeed")

	// 3. The same transfer now fails (dest rejects the message from src's pool).
	post := token_transfer.TokenTransfer(lib, src, dest, combo, combo.FinalityConfig(), true, "remove-remote-pool after", token_transfer.Args{})
	require.Error(t, post.Run(ctx), "token transfer should fail after the remote pool is removed")
}

// resolveComboTokens resolves the src and dest token addresses for a combo as
// family-native strings, using each chain family's registered address resolver.
func resolveComboTokens(t *testing.T, lib ccv.Lib, src, dest uint64, combo common.TokenCombination) (srcToken, destToken string) {
	t.Helper()
	ds, err := lib.DataStore()
	require.NoError(t, err)

	srcFamily, err := chainsel.GetSelectorFamily(src)
	require.NoError(t, err)
	srcReg, err := chainreg.GetRegistry().Get(srcFamily)
	require.NoError(t, err)
	require.NotNil(t, srcReg.AddressResolver)

	dstFamily, err := chainsel.GetSelectorFamily(dest)
	require.NoError(t, err)
	dstReg, err := chainreg.GetRegistry().Get(dstFamily)
	require.NoError(t, err)
	require.NotNil(t, dstReg.AddressResolver)

	srcTok, err := srcReg.AddressResolver.GetToken(ds, src, combo.LocalPoolAddressRef())
	require.NoError(t, err)
	destTok, err := dstReg.AddressResolver.GetToken(ds, dest, combo.RemotePoolAddressRef())
	require.NoError(t, err)

	return srcTok.String(), destTok.String()
}
