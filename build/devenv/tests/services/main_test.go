package services_test

import (
	"flag"
	"log"
	"os"
	"testing"

	"github.com/smartcontractkit/chainlink-testing-framework/framework"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(0)
	}
	// to remove containers after the tests automatically
	_ = os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "false")
	// to isolate containers the same way we do in e2e environment
	err := framework.DefaultNetwork(nil)
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(m.Run())
}
