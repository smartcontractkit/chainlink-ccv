package chainreg

import (
	"testing"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

type stubExecutorInfo struct{}

func (stubExecutorInfo) ExecutorTransmitterKeyName() string { return "transmitter-key" }

func (stubExecutorInfo) ExecutorTransmitterAddress(keys services.BootstrapKeys) string {
	return "transmitter-addr"
}

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

func TestRegistryGetExecutorTransmitterInfo(t *testing.T) {
	r := NewRegistry()
	if err := r.Add("evm", Registration{ExecutorInfo: stubExecutorInfo{}}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	reg, err := r.Get("evm")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if reg.ExecutorInfo == nil {
		t.Fatal("ExecutorInfo is nil")
	}
	if got := reg.ExecutorInfo.ExecutorTransmitterKeyName(); got != "transmitter-key" {
		t.Fatalf("ExecutorTransmitterKeyName() = %q, want transmitter-key", got)
	}
	if got := reg.ExecutorInfo.ExecutorTransmitterAddress(services.BootstrapKeys{}); got != "transmitter-addr" {
		t.Fatalf("ExecutorTransmitterAddress() = %q, want transmitter-addr", got)
	}
}

func TestRegistryAddMergesExecutorInfo(t *testing.T) {
	r := NewRegistry()
	if err := r.Add("solana", Registration{
		ExtraArgsSerializers: map[uint8]ExtraArgsSerializer{
			1: func(cciptestinterfaces.ExtraArgsDataProvider) (cciptestinterfaces.GenericExtraArgs, error) {
				return nil, nil
			},
		},
	}); err != nil {
		t.Fatalf("first Add() error = %v", err)
	}
	if err := r.Add("solana", Registration{ExecutorInfo: stubExecutorInfo{}}); err != nil {
		t.Fatalf("second Add() error = %v", err)
	}

	reg, err := r.Get("solana")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if reg.ExecutorInfo == nil {
		t.Fatal("ExecutorInfo was not merged")
	}
	if _, ok := r.GetExtraArgsSerializer("solana", 1); !ok {
		t.Fatal("ExtraArgsSerializer was not preserved")
	}
}
