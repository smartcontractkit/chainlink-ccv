package e2e

import (
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	"github.com/smartcontractkit/chainlink-testing-framework/wasp"
)

type ExampleGun struct {
	rpc   string
	c     *ethclient.Client
	auth  *bind.TransactOpts
	addrs []datastore.AddressRef
}

func NewEVMTransactionGun(rpc string, c *ethclient.Client, auth *bind.TransactOpts, addrs []datastore.AddressRef) *ExampleGun {
	fmt.Printf("%-30s %-30s %-40s %-30s\n", "Selector", "Type", "Address", "Version")
	fmt.Println("--------------------------------------------------------------------------------------------------------------")
	for _, ref := range addrs {
		fmt.Printf("%-30d %-30s %-40s %-30s\n", ref.ChainSelector, ref.Type, ref.Address, ref.Version)
	}
	return &ExampleGun{
		rpc:   rpc,
		c:     c,
		auth:  auth,
		addrs: addrs,
	}
}

// Call implements example gun call, assertions on response bodies should be done here
func (m *ExampleGun) Call(_ *wasp.Generator) *wasp.Response {
	// TODO: call real client contract and publish messages
	return &wasp.Response{Data: ""}
}
