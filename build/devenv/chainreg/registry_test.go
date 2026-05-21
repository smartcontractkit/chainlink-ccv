package chainreg

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func TestRegistryGetExtraArgsSerializer(t *testing.T) {
	r := NewRegistry()
	serializer := func(cciptestinterfaces.ExtraArgsDataProvider) (cciptestinterfaces.GenericExtraArgs, error) {
		return cciptestinterfaces.GenericExtraArgs{1}, nil
	}

	if err := r.Add("evm", Registration{
		ExtraArgsSerializers: map[uint8]ExtraArgsSerializer{1: serializer},
	}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	got, ok := r.GetExtraArgsSerializer("evm", 1)
	if !ok {
		t.Fatal("GetExtraArgsSerializer() did not find serializer")
	}
	extraArgs, err := got(nil)
	if err != nil {
		t.Fatalf("serializer() error = %v", err)
	}
	if string(extraArgs) != string(cciptestinterfaces.GenericExtraArgs{1}) {
		t.Fatalf("serializer() = %v, want %v", extraArgs, cciptestinterfaces.GenericExtraArgs{1})
	}
}

func TestRegistryAddMergesPartialRegistrations(t *testing.T) {
	r := NewRegistry()
	serializer := func(cciptestinterfaces.ExtraArgsDataProvider) (cciptestinterfaces.GenericExtraArgs, error) {
		return nil, nil
	}
	loader := func([]*ctfblockchain.Output) (map[string]any, error) {
		return map[string]any{"loaded": true}, nil
	}

	if err := r.Add("canton", Registration{
		ExtraArgsSerializers: map[uint8]ExtraArgsSerializer{1: serializer},
	}); err != nil {
		t.Fatalf("first Add() error = %v", err)
	}
	if err := r.Add("canton", Registration{
		ChainConfigLoader: loader,
	}); err != nil {
		t.Fatalf("second Add() error = %v", err)
	}

	reg, err := r.Get("canton")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if reg.ChainConfigLoader == nil {
		t.Fatal("ChainConfigLoader was not merged")
	}
	if _, ok := r.GetExtraArgsSerializer("canton", 1); !ok {
		t.Fatal("ExtraArgsSerializer was not preserved")
	}
}
