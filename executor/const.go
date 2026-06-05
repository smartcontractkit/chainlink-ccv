package executor

const (
	DefaultConfigFile = "/etc/config.toml"

	// DefaultEVMTransmitterKeyName is the full keystore path of the ECDSA key used
	// to sign and submit OffRamp transactions on EVM chains. The evm/tx/ prefix
	// follows the evmkeys convention so that TxKey can use it directly with
	// WithNoPrefix(). The bootstrap framework creates or loads it on startup;
	// devenv uses it to look up the funded on-chain address after the container
	// is running.
	DefaultEVMTransmitterKeyName = "evm/tx/executor_evm_transmitter_key"

	// DefaultSolanaTransmitterKeyName is the full keystore path of the Ed25519 key used
	// to sign and submit OffRamp transactions on Solana chains. The solana/tx/ prefix
	// follows the solkeys convention so that TxKey can use it directly with WithNoPrefix().
	// The bootstrap framework creates or loads it on startup; devenv uses it to look up
	// the funded on-chain address after the container is running.
	DefaultSolanaTransmitterKeyName = "solana/tx/executor_solana_transmitter_key"
)
