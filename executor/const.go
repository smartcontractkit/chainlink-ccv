package executor

const (
	DefaultConfigFile = "/etc/config.toml"

	// DefaultEVMTransmitterKeyName is the name of the ECDSA key in the keystore
	// used to sign and submit OffRamp transactions on EVM chains. This name is
	// declared via bootstrap.WithKey in the executor entrypoint so the bootstrap
	// framework creates or loads it on startup; devenv uses it to look up the
	// funded on-chain address after the container is running.
	DefaultEVMTransmitterKeyName = "executor_evm_transmitter_key"
)
