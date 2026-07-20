package jobs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrapCSAKeyProvider(t *testing.T) {
	key, err := BootstrapCSAKeyProvider("public-key").CSAKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "public-key", key)

	_, err = BootstrapCSAKeyProvider("").CSAKey(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestRegisterNodeWithJD_RequiresDependencies(t *testing.T) {
	_, err := RegisterNodeWithJD(context.Background(), nil, "nop", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CSA key provider")

	_, err = RegisterNodeWithJD(context.Background(), BootstrapCSAKeyProvider("public-key"), "nop", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JD client")
}
