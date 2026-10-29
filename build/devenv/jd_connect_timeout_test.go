package ccv

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJDSectionDecodesNodeConnectTimeout guards the [jd] wrapper: the third-party
// jd.Input fields must stay inlined alongside node_connect_timeout under strict
// decoding (as Load does), and the key must stay optional with an empty fallback.
func TestJDSectionDecodesNodeConnectTimeout(t *testing.T) {
	const withKey = `
version = 1

[jd]
  csa_encryption_key = "d1093c0060d50a3c89c189b2e485da5a3ce57f3dcb38ab7e2c0d5f0bb2314a44"
  image = "job-distributor:local"
  node_connect_timeout = "5m"
`
	var c Cfg
	dec := toml.NewDecoder(strings.NewReader(withKey))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&c), "[jd] node_connect_timeout must decode under strict mode")
	require.NotNil(t, c.JD)
	assert.Equal(t, "5m", c.JD.NodeConnectTimeout)
	assert.Equal(t, "job-distributor:local", c.JD.Image, "embedded jd.Input fields must stay inlined")

	const withoutKey = `
version = 1

[jd]
  csa_encryption_key = "d1093c0060d50a3c89c189b2e485da5a3ce57f3dcb38ab7e2c0d5f0bb2314a44"
  image = "job-distributor:local"
`
	var c2 Cfg
	dec2 := toml.NewDecoder(strings.NewReader(withoutKey))
	dec2.DisallowUnknownFields()
	require.NoError(t, dec2.Decode(&c2))
	assert.Empty(t, c2.JD.NodeConnectTimeout, "absent node_connect_timeout must fall back to the default")
}
