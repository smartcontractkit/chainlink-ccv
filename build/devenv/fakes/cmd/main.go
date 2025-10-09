package main

import (
	"log"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/fake"
	"github.com/smartcontractkit/devenv/ccip17/fakes/pkg/offchainstorage"
)

func main() {
	// Initialize the fake data provider
	_, err := fake.NewFakeDataProvider(&fake.Input{Port: fake.DefaultFakeServicePort})
	if err != nil {
		panic(err)
	}

	// Create and configure the offchain storage API
	api := offchainstorage.NewOffChainStorageAPI()

	// Populate with test data (10 messages by default)
	api.PopulateWithTestData(10)
	log.Println("Populated fake storage with 10 test messages")

	// Register the API endpoints
	err = api.Register()
	if err != nil {
		panic(err)
	}

	log.Printf("Fake offchain storage API running on port %d", fake.DefaultFakeServicePort)

	// Keep the server running
	select {}
}
