package evm

import (
	sel "github.com/smartcontractkit/chain-selectors"
)

// cctpDomains maps an EVM chain selector to the Circle domain used for cross-chain
// USDC transfers.
// https://developers.circle.com/cctp/cctp-supported-blockchains
//
// This is the EVM catalog only. Every other chain family owns its own table: the Solana
// table lives in chainlink-ccip-solana/pkg/accessors.
var cctpDomains = map[uint64]uint32{
	// ---------- Mainnet Domains ----------
	sel.ETHEREUM_MAINNET.Selector:              0,
	sel.AVALANCHE_MAINNET.Selector:             1,
	sel.ETHEREUM_MAINNET_OPTIMISM_1.Selector:   2,
	sel.ETHEREUM_MAINNET_ARBITRUM_1.Selector:   3,
	sel.ETHEREUM_MAINNET_BASE_1.Selector:       6,
	sel.POLYGON_MAINNET.Selector:               7,
	sel.ETHEREUM_MAINNET_UNICHAIN_1.Selector:   10,
	sel.ETHEREUM_MAINNET_LINEA_1.Selector:      11,
	sel.CODEX_MAINNET.Selector:                 12,
	sel.SONIC_MAINNET.Selector:                 13,
	sel.ETHEREUM_MAINNET_WORLDCHAIN_1.Selector: 14,
	sel.MONAD_MAINNET.Selector:                 15,
	sel.SEI_MAINNET.Selector:                   16,
	sel.BINANCE_SMART_CHAIN_MAINNET.Selector:   17,
	sel.XDC_MAINNET.Selector:                   18,
	sel.HYPERLIQUID_MAINNET.Selector:           19,
	sel.ETHEREUM_MAINNET_INK_1.Selector:        21,
	sel.PLUME_MAINNET.Selector:                 22,
	// ---------- Testnet Domains ----------
	sel.ETHEREUM_TESTNET_SEPOLIA.Selector:              0,
	sel.AVALANCHE_TESTNET_FUJI.Selector:                1,
	sel.ETHEREUM_TESTNET_SEPOLIA_OPTIMISM_1.Selector:   2,
	sel.ETHEREUM_TESTNET_SEPOLIA_ARBITRUM_1.Selector:   3,
	sel.ETHEREUM_TESTNET_SEPOLIA_BASE_1.Selector:       6,
	sel.POLYGON_TESTNET_AMOY.Selector:                  7,
	sel.ETHEREUM_TESTNET_SEPOLIA_UNICHAIN_1.Selector:   10,
	sel.ETHEREUM_TESTNET_SEPOLIA_LINEA_1.Selector:      11,
	sel.CODEX_TESTNET.Selector:                         12,
	sel.SONIC_TESTNET_BLAZE.Selector:                   13,
	sel.ETHEREUM_TESTNET_SEPOLIA_WORLDCHAIN_1.Selector: 14,
	sel.MONAD_TESTNET.Selector:                         15,
	sel.SEI_TESTNET_ATLANTIC.Selector:                  16,
	sel.BINANCE_SMART_CHAIN_TESTNET.Selector:           17,
	sel.XDC_TESTNET.Selector:                           18,
	sel.HYPERLIQUID_TESTNET.Selector:                   19,
	sel.INK_TESTNET_SEPOLIA.Selector:                   21,
	sel.PLUME_TESTNET.Selector:                         22,
	// ---------- Domain for local testing ----------
	sel.GETH_TESTNET.Selector:  100,
	sel.GETH_DEVNET_2.Selector: 101,
	sel.GETH_DEVNET_3.Selector: 102,
}

// CCTPDomain returns the Circle CCTP domain for an EVM chain selector.
func CCTPDomain(selector uint64) (uint32, bool) {
	domain, ok := cctpDomains[selector]
	return domain, ok
}
