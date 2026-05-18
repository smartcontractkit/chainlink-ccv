package evm

import (
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
)

func init() {
	// Register EVM with chainreg
	if err := chainreg.Register(chainsel.FamilyEVM, chainreg.Registration{
		ImplFactory:       &ImplFactory{},
		CLDFProvider:      NewCLDFProviderFactory(),
		ChainConfigLoader: ChainConfigLoader,
		VerifierModifier:  VerifierModifier,
		ExecutorModifier:  ExecutorModifier,
		ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
			1: BuildEVMExtraArgsV1,
			2: BuildEVMExtraArgsV2,
			3: SerializeMessageV3ExtraArgs,
		},
	}); err != nil {
		panic("evm chainreg: " + err.Error())
	}

	// Cross-family extra-args defaults until product repos register their own serializers.
	// TODO: Move Canton serializer registration into the Canton product repo.
	if err := chainreg.Register(chainsel.FamilyCanton, chainreg.Registration{
		ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
			1: BuildEVMExtraArgsV1,
			2: BuildEVMExtraArgsV2,
			3: SerializeMessageV3ExtraArgs,
		},
	}); err != nil {
		panic("canton extra-args chainreg: " + err.Error())
	}
	// TODO: Move Solana serializer registration into the Solana product repo.
	if err := chainreg.Register(chainsel.FamilySolana, chainreg.Registration{
		ExtraArgsSerializers: map[uint8]chainreg.ExtraArgsSerializer{
			1: BuildSVMExtraArgsV1,
		},
	}); err != nil {
		panic("solana extra-args chainreg: " + err.Error())
	}
}
