package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenCombinationAddressRefsUseReciprocalPoolInstanceQualifiers(t *testing.T) {
	ccvs := []string{DefaultCommitteeVerifierQualifier}
	forward := newTokenCombination(BurnMintTokenPoolType, "2.0.0", ccvs, LockReleaseTokenPoolType, "2.0.0", ccvs)
	reverse := newTokenCombination(LockReleaseTokenPoolType, "2.0.0", ccvs, BurnMintTokenPoolType, "2.0.0", ccvs)

	require.Equal(t, forward.RemotePoolAddressRef(), reverse.LocalPoolAddressRef())
	require.Equal(t, forward.LocalPoolAddressRef(), reverse.RemotePoolAddressRef())
	require.NotEqual(t, forward.LocalPoolAddressRef().Qualifier, forward.RemotePoolAddressRef().Qualifier)
	require.NotContains(t, forward.LocalPoolAddressRef().Qualifier, ":local")
	require.NotContains(t, forward.RemotePoolAddressRef().Qualifier, ":remote")
	require.Contains(t, forward.LocalPoolAddressRef().Qualifier, "::BurnMintTokenPool")
	require.Contains(t, forward.RemotePoolAddressRef().Qualifier, "::LockReleaseTokenPool")
}
