package main

import (
	"log"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"

	"github.com/smartcontractkit/devenv/ccip17/fakes/pkg/cctp"
	"github.com/smartcontractkit/devenv/ccip17/fakes/pkg/offchainstorage"
)

func main() {
	// Initialize the fake data provider
	_, err := fake.NewFakeDataProvider(&fake.Input{Port: fake.DefaultFakeServicePort})
	if err != nil {
		panic(err)
	}

	// Create and configure the offchain storage API
	offchainStorage := offchainstorage.NewOffChainStorageAPI()
	if err = offchainStorage.Register(); err != nil {
		panic(err)
	}
	log.Printf("Fake offchain storage API running on port %d", fake.DefaultFakeServicePort)

	cctpAttestations := cctp.NewAttestationAPI()
	if err = cctpAttestations.Register(); err != nil {
		panic(err)
	}
	log.Printf("Fake CCTP Attestation API running on port %d", fake.DefaultFakeServicePort)

	// Keep the server running
	select {}
}
