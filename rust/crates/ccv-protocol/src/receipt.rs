//! Receipt structure parsing and CCV+executor hash validation.
//!
//! Receipt structure from OnRamp.sol `_getReceipts()`:
//! - Array size: ccvs.length + tokenAmounts.length + 2 (executor + network fee)
//! - CCVs: indices [0 .. ccvs.length-1]
//! - Executor: index [length-2]
//! - Network fee: index [length-1]
//! - Token: index [length-3] (if tokenAmounts.length > 0)
//!
//! Example with 2 CCVs, 1 token: [CCV0, CCV1, Token, Executor, NetworkFee]
//! Example with 2 CCVs, 0 tokens: [CCV0, CCV1, Executor, NetworkFee]

use alloy_primitives::{B256, keccak256};

use crate::types::{MAX_CCVS_PER_MESSAGE, ReceiptWithBlob, UnknownAddress};
use crate::{Message, ProtocolError};

/// Parsed receipt structure from an OnRamp event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptStructure {
    pub ccv_receipts: Vec<ReceiptWithBlob>,
    pub token_receipts: Vec<ReceiptWithBlob>,
    pub executor_receipt: ReceiptWithBlob,
    pub ccv_addresses: Vec<UnknownAddress>,
    pub executor_address: UnknownAddress,
}

/// Parses receipts according to the CCIP OnRamp structure.
/// Mirrors Go `protocol.ParseReceiptStructure`.
pub fn parse_receipt_structure(
    receipts: &[ReceiptWithBlob],
    num_ccv_blobs: usize,
    num_token_transfers: usize,
) -> Result<ReceiptStructure, ProtocolError> {
    if receipts.is_empty() {
        return Err(ProtocolError::NoReceipts);
    }
    // Go requires an exact count match: CCVs + Tokens + executor + network fee.
    let expected = num_ccv_blobs + num_token_transfers + 2;
    let mismatch = || ProtocolError::UnexpectedReceiptCount {
        got: receipts.len(),
        expected,
        ccvs: num_ccv_blobs,
        tokens: num_token_transfers,
    };
    if receipts.len() != expected {
        return Err(mismatch());
    }

    // With the exact count verified, every extraction below is provably in
    // bounds; the accessors stay checked regardless — no panics.
    let ccv_receipts = receipts.get(..num_ccv_blobs).ok_or_else(mismatch)?.to_vec();
    let executor_receipt = receipts.iter().rev().nth(1).ok_or_else(mismatch)?.clone();
    let token_receipts = if num_token_transfers > 0 {
        vec![receipts.iter().rev().nth(2).ok_or_else(mismatch)?.clone()]
    } else {
        Vec::new()
    };

    let ccv_addresses = ccv_receipts.iter().map(|r| r.issuer.clone()).collect();
    let executor_address = executor_receipt.issuer.clone();
    Ok(ReceiptStructure {
        ccv_receipts,
        token_receipts,
        executor_receipt,
        ccv_addresses,
        executor_address,
    })
}

/// Calculates keccak256(addressLength u8 || ccv1 || ... || ccvN || executor).
/// Matches Go `protocol.ComputeCCVAndExecutorHash` and Solidity
/// `MessageV1Codec._computeCCVAndExecutorHash()`. All addresses must have the
/// same length as the executor address.
pub fn compute_ccv_and_executor_hash(
    ccv_addresses: &[UnknownAddress],
    executor_address: &UnknownAddress,
) -> Result<B256, ProtocolError> {
    if ccv_addresses.len() > MAX_CCVS_PER_MESSAGE {
        return Err(ProtocolError::TooManyCcvs(ccv_addresses.len()));
    }
    let address_length = executor_address.len();
    if address_length == 0 {
        return Err(ProtocolError::EmptyExecutorAddress);
    }
    for (i, ccv) in ccv_addresses.iter().enumerate() {
        if ccv.len() != address_length {
            return Err(ProtocolError::CcvAddressLengthMismatch {
                index: i,
                got: ccv.len(),
                expected: address_length,
            });
        }
    }
    let mut encoded = Vec::with_capacity(1 + (ccv_addresses.len() + 1) * address_length);
    // Matches Go's `byte(addressLength)` (nolint:gosec): UnknownAddress is
    // documented as at most 255 bytes; EVM addresses are 20.
    #[allow(clippy::cast_possible_truncation)]
    encoded.push(address_length as u8);
    for ccv in ccv_addresses {
        encoded.extend_from_slice(ccv);
    }
    encoded.extend_from_slice(executor_address);
    Ok(keccak256(encoded))
}

/// Verifies that the message's `ccv_and_executor_hash` matches the hash computed
/// from the CCV and executor addresses extracted from the receipt blobs.
/// Mirrors Go `protocol.ValidateCCVAndExecutorHash`.
pub fn validate_ccv_and_executor_hash(
    message: &Message,
    receipt_blobs: &[ReceiptWithBlob],
) -> Result<(), ProtocolError> {
    if receipt_blobs.is_empty() {
        return Err(ProtocolError::NoReceipts);
    }
    let num_token_transfers = usize::from(message.token_transfer.is_some());
    if receipt_blobs.len() < num_token_transfers + 2 {
        return Err(ProtocolError::InsufficientReceipts {
            got: receipt_blobs.len(),
            needed: num_token_transfers + 2,
        });
    }
    let num_ccv_blobs = receipt_blobs.len() - num_token_transfers - 2;
    let structure = parse_receipt_structure(receipt_blobs, num_ccv_blobs, num_token_transfers)?;
    message.validate_ccv_and_executor_hash(&structure.ccv_addresses, &structure.executor_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    use crate::types::{ChainSelector, Finality, SequenceNumber};

    fn receipt(issuer_byte: u8) -> ReceiptWithBlob {
        ReceiptWithBlob {
            issuer: vec![issuer_byte; 20],
            blob: vec![],
            extra_args: vec![],
            dest_gas_limit: 100_000,
            dest_bytes_overhead: 32,
            fee_token_amount: U256::from(1u64),
        }
    }

    fn ccv_hash(ccvs: &[u8], executor: u8) -> B256 {
        let addrs: Vec<UnknownAddress> = ccvs.iter().map(|&b| vec![b; 20]).collect();
        compute_ccv_and_executor_hash(&addrs, &vec![executor; 20]).unwrap()
    }

    fn msg_with_hash(hash: B256, with_token: bool) -> Message {
        let token_transfer = with_token.then(|| crate::TokenTransfer {
            version: 1,
            amount: U256::from(7u64),
            source_pool_address: vec![0x44; 20],
            source_token_address: vec![0x55; 20],
            dest_token_address: vec![0x66; 20],
            token_receiver: vec![0x77; 20],
            extra_data: vec![],
        });
        Message {
            sender: vec![0xcc; 32],
            data: vec![],
            on_ramp_address: vec![0xaa; 32],
            token_transfer,
            off_ramp_address: vec![0xbb; 32],
            dest_blob: vec![],
            receiver: vec![0xdd; 32],
            source_chain_selector: ChainSelector(1),
            dest_chain_selector: ChainSelector(2),
            sequence_number: SequenceNumber(1),
            execution_gas_limit: 1,
            ccip_receive_gas_limit: 1,
            finality: Finality(0),
            ccv_and_executor_hash: hash,
            version: 1,
        }
    }

    #[test]
    fn hash_rejects_too_many_ccvs() {
        let ccvs: Vec<UnknownAddress> = (0..=u8::MAX).map(|i| vec![i; 20]).collect();
        assert_eq!(ccvs.len(), 256);
        assert!(matches!(
            compute_ccv_and_executor_hash(&ccvs, &vec![0x33; 20]),
            Err(ProtocolError::TooManyCcvs(256))
        ));
    }

    #[test]
    fn parses_structure_without_tokens() {
        // [CCV0, CCV1, Executor, NetworkFee]
        let receipts = vec![receipt(0x11), receipt(0x22), receipt(0x33), receipt(0xee)];
        let s = parse_receipt_structure(&receipts, 2, 0).unwrap();
        assert_eq!(s.ccv_addresses, vec![vec![0x11; 20], vec![0x22; 20]]);
        assert_eq!(s.executor_address, vec![0x33; 20]);
        assert!(s.token_receipts.is_empty());
    }

    #[test]
    fn parses_structure_with_tokens() {
        // [CCV0, CCV1, Token, Executor, NetworkFee]
        let receipts = vec![
            receipt(0x11),
            receipt(0x22),
            receipt(0x99),
            receipt(0x33),
            receipt(0xee),
        ];
        let s = parse_receipt_structure(&receipts, 2, 1).unwrap();
        assert_eq!(s.token_receipts.len(), 1);
        assert_eq!(s.token_receipts[0].issuer, vec![0x99; 20]);
        assert_eq!(s.executor_address, vec![0x33; 20]);
    }

    #[test]
    fn rejects_wrong_counts() {
        assert!(matches!(
            parse_receipt_structure(&[], 0, 0),
            Err(ProtocolError::NoReceipts)
        ));
        let receipts = vec![receipt(0x11), receipt(0x33), receipt(0xee)];
        // 1 CCV + executor + network fee = 3, but claim 2 CCVs
        assert!(matches!(
            parse_receipt_structure(&receipts, 2, 0),
            Err(ProtocolError::UnexpectedReceiptCount { .. })
        ));
        // More CCVs claimed than receipts present.
        assert!(matches!(
            parse_receipt_structure(&receipts, 5, 0),
            Err(ProtocolError::UnexpectedReceiptCount { .. })
        ));
        // Too few receipts for an executor at all.
        assert!(matches!(
            parse_receipt_structure(&[receipt(0x11)], 0, 0),
            Err(ProtocolError::UnexpectedReceiptCount { .. })
        ));
        // Token transfer claimed but no room for a token receipt.
        assert!(matches!(
            parse_receipt_structure(&[receipt(0x11), receipt(0x33)], 0, 1),
            Err(ProtocolError::UnexpectedReceiptCount { .. })
        ));
        // The exact-count check rejects extras.
        assert!(matches!(
            parse_receipt_structure(&[receipt(0x11), receipt(0x33), receipt(0xee), receipt(0x99)], 1, 0),
            Err(ProtocolError::UnexpectedReceiptCount { .. })
        ));
    }

    #[test]
    fn validates_hash_from_receipts() {
        let hash = ccv_hash(&[0x11, 0x22], 0x33);
        let receipts = vec![receipt(0x11), receipt(0x22), receipt(0x33), receipt(0xee)];
        let msg = msg_with_hash(hash, false);
        validate_ccv_and_executor_hash(&msg, &receipts).unwrap();

        // Empty receipts.
        assert!(matches!(
            validate_ccv_and_executor_hash(&msg, &[]),
            Err(ProtocolError::NoReceipts)
        ));

        // Same receipts but the message carries a token transfer: the parser now
        // reads only 1 CCV ([0x11]) and treats 0x22 as the token receipt, so the
        // recomputed hash no longer matches.
        let msg = msg_with_hash(hash, true);
        assert!(matches!(
            validate_ccv_and_executor_hash(&msg, &receipts),
            Err(ProtocolError::CcvAndExecutorHashMismatch { .. })
        ));

        // Too few receipts for the claimed token transfer.
        let msg = msg_with_hash(hash, true);
        let receipts = vec![receipt(0x33), receipt(0xee)];
        assert!(matches!(
            validate_ccv_and_executor_hash(&msg, &receipts),
            Err(ProtocolError::InsufficientReceipts { .. })
        ));

        // Wrong executor in receipts -> hash mismatch.
        let receipts = vec![receipt(0x11), receipt(0x22), receipt(0x44), receipt(0xee)];
        let msg = msg_with_hash(hash, false);
        assert!(matches!(
            validate_ccv_and_executor_hash(&msg, &receipts),
            Err(ProtocolError::CcvAndExecutorHashMismatch { .. })
        ));
    }
}
