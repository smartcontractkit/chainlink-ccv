//! Shared fixtures for the ccv-chainaccess-grpc integration tests.

#![allow(dead_code)] // each test binary uses a different subset

use alloy::primitives::{Address, B256, Bytes, U256, address, b256};
use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;
use hex_literal::hex;

use ccv_chainaccess::evm::OnRamp;
use ccv_protocol::ChainSelector;

pub const CHAIN_SELECTOR: ChainSelector = ChainSelector(16015286601757825753);
pub const DEST_CHAIN_SELECTOR: u64 = 5009297550715157269;

// Golden message (no token transfer), produced by the Go protocol package.
pub const ENCODED_MESSAGE_NO_TOKEN: &[u8] = &hex!(
    "01de41ba4fc9d91ad945849994fc9c7b15000000000000002a0007a12000030d4000000001"
    "13a7b9b0c5f3ba0823991a0f2fccdb822f02084cde959b3b1a33f5b19ce7b4cf"
    "20000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "20000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "20000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"
    "20000000000000000000000000dddddddddddddddddddddddddddddddddddddddd"
    "0003010203" "0000" "000a" "68656c6c6f2063636970"
);
pub const MESSAGE_ID_NO_TOKEN: B256 = b256!("8527b04a622efd89664aeaa2269dcdf2f4f46898e2776aa144f874bace7be211");

pub const ON_RAMP: Address = address!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
pub const SENDER: Address = address!("cccccccccccccccccccccccccccccccccccccccc");
pub const RMN_REMOTE: Address = address!("9999999999999999999999999999999999999999");

pub fn receipt(issuer_byte: u8) -> OnRamp::Receipt {
    OnRamp::Receipt {
        issuer: Address::from([issuer_byte; 20]),
        destGasLimit: 100_000,
        destBytesOverhead: 32,
        feeTokenAmount: U256::from(1u64),
        extraArgs: Bytes::from(vec![0x01, 0x02]),
    }
}

/// A fully valid CCIPMessageSent event whose embedded message is the Go golden
/// encoding (2 CCVs 0x11/0x22, executor 0x33, network fee 0x44).
pub fn valid_event() -> OnRamp::CCIPMessageSent {
    OnRamp::CCIPMessageSent {
        destChainSelector: DEST_CHAIN_SELECTOR,
        sender: SENDER,
        messageId: MESSAGE_ID_NO_TOKEN,
        feeToken: Address::ZERO,
        tokenAmountBeforeTokenPoolFees: U256::ZERO,
        encodedMessage: Bytes::from(ENCODED_MESSAGE_NO_TOKEN.to_vec()),
        receipts: vec![receipt(0x11), receipt(0x22), receipt(0x33), receipt(0x44)],
        verifierBlobs: vec![Bytes::from(vec![0xb1; 4]), Bytes::from(vec![0xb2; 4])],
    }
}

pub fn valid_log(block_number: u64) -> Log {
    let event = valid_event();
    let topics = event.encode_topics().into_iter().map(|t| t.0).collect::<Vec<B256>>();
    Log {
        inner: alloy::primitives::Log::new_unchecked(ON_RAMP, topics, event.encode_data().into()),
        block_hash: None,
        block_number: Some(block_number),
        block_timestamp: Some(1_700_000_000),
        transaction_hash: Some(b256!(
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        )),
        transaction_index: Some(0),
        log_index: Some(0),
        removed: false,
    }
}

/// Minimal eth_getBlockByNumber response JSON that Alloy can deserialize.
pub fn block_json(n: u64) -> serde_json::Value {
    serde_json::json!({
        "number": format!("0x{n:x}"),
        "hash": format!("0x{n:064x}"),
        "parentHash": format!("0x{:064x}", n.saturating_sub(1)),
        "timestamp": "0x65f1e200",
        "nonce": "0x0000000000000000",
        "sha3Uncles": format!("0x{:064x}", 0),
        "logsBloom": format!("0x{:0512x}", 0),
        "transactionsRoot": format!("0x{:064x}", 0),
        "stateRoot": format!("0x{:064x}", 0),
        "receiptsRoot": format!("0x{:064x}", 0),
        "miner": "0x0000000000000000000000000000000000000000",
        "difficulty": "0x0",
        "extraData": "0x",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x0",
        "baseFeePerGas": "0x3b9aca00",
        "mixHash": format!("0x{:064x}", 0),
        "transactions": [],
        "uncles": [],
    })
}
