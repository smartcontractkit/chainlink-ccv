package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/executor"
)

func TestNewFactory(t *testing.T) {
	f := NewFactory()
	require.NotNil(t, f)
	assert.Nil(t, f.coordinator)
	assert.Nil(t, f.profiler)
}

func TestFactory_Stop_NilFields(t *testing.T) {
	f := NewFactory()
	require.NoError(t, f.Stop(context.Background()))
}

func TestFactory_Start_InvalidTOML(t *testing.T) {
	f := NewFactory()
	spec := bootstrap.JobSpec{AppConfig: "not valid toml =="}
	err := f.Start(context.Background(), spec, bootstrap.ServiceDeps{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "failed to decode executor config"), "unexpected error: %v", err)
}

func TestFactory_Start_EmptyConfig(t *testing.T) {
	// Empty TOML is valid; validation fails because required fields are absent.
	f := NewFactory()
	spec := bootstrap.JobSpec{AppConfig: ""}
	err := f.Start(context.Background(), spec, bootstrap.ServiceDeps{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "failed to normalize executor config"), "unexpected error: %v", err)
}

func TestSetupMonitoring_Disabled(t *testing.T) {
	lggr := logger.Test(t)
	m := SetupMonitoring(lggr, executorsvc.MonitoringConfig{Enabled: false})
	require.NotNil(t, m)
}

func TestSetupMonitoring_EnabledButNotBeholder(t *testing.T) {
	lggr := logger.Test(t)
	m := SetupMonitoring(lggr, executorsvc.MonitoringConfig{Enabled: true, Type: "noop"})
	require.NotNil(t, m)
}
