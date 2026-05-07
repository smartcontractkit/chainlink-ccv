package executor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
)

func TestApplyDefaults(t *testing.T) {
	t.Run("DB name defaults to ContainerName-db", func(t *testing.T) {
		in := &Input{ContainerName: "my-executor"}
		ApplyDefaults(in)
		require.NotNil(t, in.DB)
		assert.Equal(t, "my-executor-db", in.DB.Name)
	})

	t.Run("multiple executors get distinct DB names", func(t *testing.T) {
		in1 := &Input{ContainerName: "executor-1"}
		in2 := &Input{ContainerName: "executor-2"}
		ApplyDefaults(in1)
		ApplyDefaults(in2)
		assert.NotEqual(t, in1.DB.Name, in2.DB.Name)
	})

	t.Run("explicit DB name is preserved", func(t *testing.T) {
		in := &Input{
			ContainerName: "my-executor",
			DB:            &DBInput{Name: "custom-db", Image: DefaultExecutorDBImage},
		}
		ApplyDefaults(in)
		assert.Equal(t, "custom-db", in.DB.Name)
	})

	t.Run("image defaults applied", func(t *testing.T) {
		in := &Input{ContainerName: "e"}
		ApplyDefaults(in)
		assert.Equal(t, DefaultExecutorImage, in.Image)
		assert.Equal(t, DefaultExecutorDBImage, in.DB.Image)
	})

	t.Run("chain family defaults to EVM", func(t *testing.T) {
		in := &Input{ContainerName: "e"}
		ApplyDefaults(in)
		assert.Equal(t, chainsel.FamilyEVM, in.ChainFamily)
	})

	t.Run("mode defaults to Standalone", func(t *testing.T) {
		in := &Input{ContainerName: "e"}
		ApplyDefaults(in)
		assert.Equal(t, services.Standalone, in.Mode)
	})
}

func TestNew_NilJDInfra(t *testing.T) {
	in := &Input{ContainerName: "e"}
	ApplyDefaults(in)
	_, err := New(in, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JD infrastructure")
}
