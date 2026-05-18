package evm

import (
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
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
		ExtraArgsSerializers: map[uint8]cciptestinterfaces.ExtraArgsSerializer{
			1: BuildEVMExtraArgsV1,
			2: BuildEVMExtraArgsV2,
			3: SerializeMessageV3ExtraArgs,
		},
	}); err != nil {
		panic("evm chainreg: " + err.Error())
	}

	// Register EVM extra-args serializers
	registerExtraArgs(chainsel.FamilyEVM, 1, BuildEVMExtraArgsV1)
	registerExtraArgs(chainsel.FamilyEVM, 2, BuildEVMExtraArgsV2)
	registerExtraArgs(chainsel.FamilyEVM, 3, SerializeMessageV3ExtraArgs)

	// Cross-family extra-args defaults until product repos register their own serializers.
	registerExtraArgs(chainsel.FamilyCanton, 1, BuildEVMExtraArgsV1)
	registerExtraArgs(chainsel.FamilyCanton, 2, BuildEVMExtraArgsV2)
	registerExtraArgs(chainsel.FamilyCanton, 3, SerializeMessageV3ExtraArgs)
	cciptestinterfaces.RegisterExtraArgsSerializer(
		cciptestinterfaces.ExtraArgsSerializerEntry{Family: chainsel.FamilySolana, Version: 1},
		BuildSVMExtraArgsV1,
	)
}

func registerExtraArgs(family string, version uint8, fn cciptestinterfaces.ExtraArgsSerializer) {
	cciptestinterfaces.RegisterExtraArgsSerializer(
		cciptestinterfaces.ExtraArgsSerializerEntry{Family: family, Version: version},
		fn,
	)
}
