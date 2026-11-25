package shared

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifierSourceChains(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"appConfig", "committeeVerifierConfig"} {
		spec := fmt.Sprintf("schemaVersion = 1\ntype = \"ccvcommitteeverifier\"\n%s = '''\ncommittee_verifier_addresses = {\"15971525489660198786\" = \"0x1\", \"5009297550715157269\" = \"0x2\"}\n'''\n", key)
		chains, err := VerifierSourceChains(spec)
		require.NoError(t, err, key)
		assert.Equal(t, []uint64{5009297550715157269, 15971525489660198786}, chains, key)
	}

	chains, err := VerifierSourceChains("schemaVersion = 1\ntype = \"ccvcommitteeverifier\"\n")
	require.NoError(t, err, "a spec without an embedded config has no recorded scope")
	assert.Nil(t, chains)

	_, err = VerifierSourceChains("schemaVersion = 1\ntype = \"ccvexecutor\"\n")
	require.Error(t, err, "wrong job type")

	_, err = VerifierSourceChains("schemaVersion = 1\ntype = \"ccvcommitteeverifier\"\ncommitteeVerifierConfig = '''\ncommittee_verifier_addresses = {\"not-a-number\" = \"0x1\"}\n'''\n")
	require.Error(t, err, "invalid chain selector")
}
