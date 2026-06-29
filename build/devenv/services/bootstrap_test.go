package services

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/pkg/monitoring"
)

// TestApplyBootstrapDefaults_PreservesMonitoring locks in the contract the devenv routing relies on:
// ApplyBootstrapDefaults must not touch a caller-set Monitoring. The component/environment loops set
// Bootstrap.Monitoring before launch, after which ApplyBootstrapDefaults runs again internally; if a
// future default clobbered Monitoring, those values would silently disappear from the bootstrap config.
func TestApplyBootstrapDefaults_PreservesMonitoring(t *testing.T) {
	mon := &monitoring.Config{Enabled: true, Type: "beholder"}

	out := ApplyBootstrapDefaults(BootstrapInput{Monitoring: mon})

	require.Same(t, mon, out.Monitoring, "ApplyBootstrapDefaults must leave a caller-set Monitoring untouched")
}

// TestApplyBootstrapDefaults_NilMonitoringStaysNil confirms ApplyBootstrapDefaults does not invent a
// Monitoring value: nil in means nil out (monitoring not configured), distinct from an explicit config.
func TestApplyBootstrapDefaults_NilMonitoringStaysNil(t *testing.T) {
	out := ApplyBootstrapDefaults(BootstrapInput{})

	require.Nil(t, out.Monitoring, "ApplyBootstrapDefaults must not populate Monitoring when unset")
}
