//! Canonical CCIP v1.7 message and token-transfer encoding.
//!
//! Matches the Go `protocol.Message` / `protocol.TokenTransfer` codecs, which in turn
//! match Solidity `MessageV1Codec._encodeMessageV1()`. All integers are big-endian.

use alloy_primitives::{B256, U256, keccak256};

use crate::types::{
    ChainSelector, Finality, SequenceNumber, UnknownAddress, MIN_SIZE_REQUIRED_MSG_FIELDS,
    MIN_SIZE_REQUIRED_MSG_TOKEN_FIELDS,
};
use crate::ProtocolError;

/// Chain-agnostic token transfer with canonical encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTransfer {
    pub amount: U256,
    pub source_pool_address: Vec<u8>,
    pub source_token_address: Vec<u8>,
    pub dest_token_address: Vec<u8>,
    pub token_receiver: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub version: u8,
}

impl TokenTransfer {
    /// Returns the canonical encoding of this token transfer.
    ///
    /// Layout: version(1) || amount(32) || 4 x (len u8 || bytes) || extraDataLen u16 || extraData.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 4 + self.encoded_len());
        buf.push(self.version);
        buf.extend_from_slice(&self.amount.to_be_bytes::<32>());
        push_len_u8(&mut buf, &self.source_pool_address);
        push_len_u8(&mut buf, &self.source_token_address);
        push_len_u8(&mut buf, &self.dest_token_address);
        push_len_u8(&mut buf, &self.token_receiver);
        push_len_u16(&mut buf, &self.extra_data);
        buf
    }

    fn encoded_len(&self) -> usize {
        self.source_pool_address.len()
            + self.source_token_address.len()
            + self.dest_token_address.len()
            + self.token_receiver.len()
            + 2
            + self.extra_data.len()
    }

    /// Decodes a token transfer from its canonical encoding. Errors on trailing bytes.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < MIN_SIZE_REQUIRED_MSG_TOKEN_FIELDS {
            return Err(ProtocolError::DataTooShort { needed: MIN_SIZE_REQUIRED_MSG_TOKEN_FIELDS, got: data.len() });
        }
        let mut r = Reader::new(data);
        let version = r.u8("version")?;
        let amount = U256::from_be_bytes::<32>(r.bytes::<32>("amount")?);
        let source_pool_address = r.len_prefixed_u8("source pool address")?;
        let source_token_address = r.len_prefixed_u8("source token address")?;
        let dest_token_address = r.len_prefixed_u8("dest token address")?;
        let token_receiver = r.len_prefixed_u8("token receiver")?;
        let extra_data = r.len_prefixed_u16("extra data")?;
        r.finish()?;
        Ok(Self { amount, source_pool_address, source_token_address, dest_token_address, token_receiver, extra_data, version })
    }
}

/// Chain-agnostic CCIP message format.
///
/// Unlike the Go struct, length prefixes are not stored as separate fields: they are
/// derived from the data on encode and validated on decode, so they can never disagree
/// with the actual lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub sender: UnknownAddress,
    pub data: Vec<u8>,
    pub on_ramp_address: UnknownAddress,
    pub token_transfer: Option<TokenTransfer>,
    pub off_ramp_address: UnknownAddress,
    pub dest_blob: Vec<u8>,
    pub receiver: UnknownAddress,
    pub source_chain_selector: ChainSelector,
    pub dest_chain_selector: ChainSelector,
    pub sequence_number: SequenceNumber,
    pub execution_gas_limit: u32,
    pub ccip_receive_gas_limit: u32,
    pub finality: Finality,
    pub ccv_and_executor_hash: B256,
    pub version: u8,
}

impl Message {
    /// Returns the canonical encoding of this message.
    /// Matches Solidity `MessageV1Codec._encodeMessageV1()`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.version);
        buf.extend_from_slice(&self.source_chain_selector.to_be_bytes());
        buf.extend_from_slice(&self.dest_chain_selector.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.execution_gas_limit.to_be_bytes());
        buf.extend_from_slice(&self.ccip_receive_gas_limit.to_be_bytes());
        buf.extend_from_slice(&self.finality.to_be_bytes());
        buf.extend_from_slice(self.ccv_and_executor_hash.as_slice());
        push_len_u8(&mut buf, &self.on_ramp_address);
        push_len_u8(&mut buf, &self.off_ramp_address);
        push_len_u8(&mut buf, &self.sender);
        push_len_u8(&mut buf, &self.receiver);
        push_len_u16(&mut buf, &self.dest_blob);
        let token_transfer_bytes = self.token_transfer.as_ref().map(TokenTransfer::encode).unwrap_or_default();
        push_len_u16(&mut buf, &token_transfer_bytes);
        push_len_u16(&mut buf, &self.data);
        buf
    }

    /// Decodes a message from its canonical encoding. Errors on trailing bytes.
    /// Matches Solidity `MessageV1Codec._decodeMessageV1()`.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < MIN_SIZE_REQUIRED_MSG_FIELDS {
            return Err(ProtocolError::DataTooShort { needed: MIN_SIZE_REQUIRED_MSG_FIELDS, got: data.len() });
        }
        let mut r = Reader::new(data);
        let version = r.u8("version")?;
        let source_chain_selector = r.u64("source chain selector")?;
        let dest_chain_selector = r.u64("dest chain selector")?;
        let sequence_number = r.u64("sequence number")?;
        let execution_gas_limit = r.u32("execution gas limit")?;
        let ccip_receive_gas_limit = r.u32("ccip receive gas limit")?;
        let finality = r.u32("finality")?;
        let ccv_and_executor_hash = B256::from_slice(&r.bytes::<32>("ccv and executor hash")?);
        let on_ramp_address = r.len_prefixed_u8("on-ramp address")?;
        let off_ramp_address = r.len_prefixed_u8("off-ramp address")?;
        let sender = r.len_prefixed_u8("sender")?;
        let receiver = r.len_prefixed_u8("receiver")?;
        let dest_blob = r.len_prefixed_u16("dest blob")?;
        let token_transfer_bytes = r.len_prefixed_u16("token transfer")?;
        let token_transfer = if token_transfer_bytes.is_empty() {
            None
        } else {
            Some(TokenTransfer::decode(&token_transfer_bytes)?)
        };
        let data = r.len_prefixed_u16("data")?;
        r.finish()?;
        Ok(Self {
            sender,
            data,
            on_ramp_address,
            token_transfer,
            off_ramp_address,
            dest_blob,
            receiver,
            source_chain_selector,
            dest_chain_selector,
            sequence_number,
            execution_gas_limit,
            ccip_receive_gas_limit,
            finality,
            ccv_and_executor_hash,
            version,
        })
    }

    /// Message ID: keccak256 of the canonical encoding.
    pub fn message_id(&self) -> B256 {
        keccak256(self.encode())
    }

    /// Verifies that `ccv_and_executor_hash` matches the hash computed from the
    /// provided CCV addresses and executor address.
    pub fn validate_ccv_and_executor_hash(
        &self,
        ccv_addresses: &[UnknownAddress],
        executor_address: &UnknownAddress,
    ) -> Result<(), ProtocolError> {
        let expected = crate::receipt::compute_ccv_and_executor_hash(ccv_addresses, executor_address)?;
        if self.ccv_and_executor_hash != expected {
            return Err(ProtocolError::CcvAndExecutorHashMismatch { expected, got: self.ccv_and_executor_hash });
        }
        Ok(())
    }
}

fn push_len_u8(buf: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() <= u8::MAX as usize, "length-prefixed u8 field exceeds 255 bytes");
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

fn push_len_u16(buf: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() <= u16::MAX as usize, "length-prefixed u16 field exceeds 65535 bytes");
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Strict big-endian cursor over a byte slice. Mirrors the Go `bytes.Reader`-based decoding.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], ProtocolError> {
        if self.data.len() - self.pos < n {
            return Err(ProtocolError::UnexpectedEof(what));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, ProtocolError> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.take(2, what)?.try_into().expect("take(2)")))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.take(4, what)?.try_into().expect("take(4)")))
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.take(8, what)?.try_into().expect("take(8)")))
    }

    fn bytes<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], ProtocolError> {
        Ok(self.take(N, what)?.try_into().expect("take(N)"))
    }

    fn len_prefixed_u8(&mut self, what: &'static str) -> Result<Vec<u8>, ProtocolError> {
        let len = self.u8(what)? as usize;
        Ok(self.take(len, what)?.to_vec())
    }

    fn len_prefixed_u16(&mut self, what: &'static str) -> Result<Vec<u8>, ProtocolError> {
        let len = self.u16(what)? as usize;
        Ok(self.take(len, what)?.to_vec())
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.pos != self.data.len() {
            return Err(ProtocolError::TrailingBytes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U256, hex as alloy_hex};
    use hex_literal::hex;

    // Golden vectors generated by running the Go protocol package
    // (see .tmp-golden in the repo history; vectors embedded below).
    const GOLDEN_CCV_HASH: [u8; 32] = hex!("13a7b9b0c5f3ba0823991a0f2fccdb822f02084cde959b3b1a33f5b19ce7b4cf");
    const GOLDEN_MESSAGE: &[u8] = &hex!(
        "01de41ba4fc9d91ad945849994fc9c7b15000000000000002a0007a12000030d4000000001"
        "13a7b9b0c5f3ba0823991a0f2fccdb822f02084cde959b3b1a33f5b19ce7b4cf"
        "20000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "20000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "20000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"
        "20000000000000000000000000dddddddddddddddddddddddddddddddddddddddd"
        "0003010203"
        "0087"
        "010000000000000000000000000000000000000000000000000de0b6b3a7640000"
        "14" "4444444444444444444444444444444444444444"
        "14" "5555555555555555555555555555555555555555"
        "20" "6666666666666666666666666666666666666666666666666666666666666666"
        "14" "7777777777777777777777777777777777777777"
        "0004" "deadbeef"
        "000a" "68656c6c6f2063636970"
    );
    const GOLDEN_MESSAGE_ID: [u8; 32] = hex!("969d89ef12e60be7faff8b1b72c6b9a95faac24cb82c77cdf009e5a580500557");
    const GOLDEN_MESSAGE_NO_TOKEN: &[u8] = &hex!(
        "01de41ba4fc9d91ad945849994fc9c7b15000000000000002a0007a12000030d4000000001"
        "13a7b9b0c5f3ba0823991a0f2fccdb822f02084cde959b3b1a33f5b19ce7b4cf"
        "20000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "20000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "20000000000000000000000000cccccccccccccccccccccccccccccccccccccccc"
        "20000000000000000000000000dddddddddddddddddddddddddddddddddddddddd"
        "0003010203"
        "0000"
        "000a" "68656c6c6f2063636970"
    );
    const GOLDEN_MESSAGE_NO_TOKEN_ID: [u8; 32] = hex!("8527b04a622efd89664aeaa2269dcdf2f4f46898e2776aa144f874bace7be211");

    fn bytes20(v: u8) -> Vec<u8> {
        vec![v; 20]
    }

    fn pad32(b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        out[32 - b.len()..].copy_from_slice(b);
        out
    }

    fn golden_token_transfer() -> TokenTransfer {
        TokenTransfer {
            version: 1,
            amount: U256::from(1_000_000_000_000_000_000u64), // 1e18
            source_pool_address: bytes20(0x44),
            source_token_address: bytes20(0x55),
            dest_token_address: vec![0x66; 32],
            token_receiver: bytes20(0x77),
            extra_data: vec![0xde, 0xad, 0xbe, 0xef],
        }
    }

    fn golden_message(token_transfer: Option<TokenTransfer>) -> Message {
        Message {
            version: crate::MESSAGE_VERSION,
            source_chain_selector: 16015286601757825753,
            dest_chain_selector: 5009297550715157269,
            sequence_number: 42,
            execution_gas_limit: 500_000,
            ccip_receive_gas_limit: 200_000,
            finality: 1,
            ccv_and_executor_hash: B256::from(GOLDEN_CCV_HASH),
            on_ramp_address: pad32(&bytes20(0xaa)),
            off_ramp_address: pad32(&bytes20(0xbb)),
            sender: pad32(&bytes20(0xcc)),
            receiver: pad32(&bytes20(0xdd)),
            dest_blob: vec![0x01, 0x02, 0x03],
            token_transfer,
            data: b"hello ccip".to_vec(),
        }
    }

    #[test]
    fn message_encode_matches_go_with_token_transfer() {
        let msg = golden_message(Some(golden_token_transfer()));
        assert_eq!(msg.encode(), GOLDEN_MESSAGE);
        assert_eq!(msg.message_id(), B256::from(GOLDEN_MESSAGE_ID));
    }

    #[test]
    fn message_encode_matches_go_without_token_transfer() {
        let msg = golden_message(None);
        assert_eq!(msg.encode(), GOLDEN_MESSAGE_NO_TOKEN);
        assert_eq!(msg.message_id(), B256::from(GOLDEN_MESSAGE_NO_TOKEN_ID));
    }

    #[test]
    fn message_decode_roundtrips_golden() {
        let msg = golden_message(Some(golden_token_transfer()));
        let decoded = Message::decode(GOLDEN_MESSAGE).expect("decode golden");
        assert_eq!(decoded, msg);
        assert_eq!(decoded.encode(), GOLDEN_MESSAGE);

        let decoded = Message::decode(GOLDEN_MESSAGE_NO_TOKEN).expect("decode golden no token");
        assert_eq!(decoded, golden_message(None));
    }

    #[test]
    fn ccv_and_executor_hash_matches_go() {
        let hash =
            crate::receipt::compute_ccv_and_executor_hash(&[bytes20(0x11), bytes20(0x22)], &bytes20(0x33)).unwrap();
        assert_eq!(hash, B256::from(GOLDEN_CCV_HASH));
    }

    #[test]
    fn decode_rejects_short_input() {
        let err = Message::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtocolError::DataTooShort { .. }));
        let err = TokenTransfer::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtocolError::DataTooShort { .. }));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut data = GOLDEN_MESSAGE_NO_TOKEN.to_vec();
        data.push(0x00);
        let err = Message::decode(&data).unwrap_err();
        assert!(matches!(err, ProtocolError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let truncated = &GOLDEN_MESSAGE[..GOLDEN_MESSAGE.len() - 3];
        let err = Message::decode(truncated).unwrap_err();
        assert!(matches!(err, ProtocolError::UnexpectedEof(_)));
    }

    #[test]
    fn hash_rejects_inconsistent_addresses() {
        let err = crate::receipt::compute_ccv_and_executor_hash(&[bytes20(0x11), vec![0x22; 32]], &bytes20(0x33))
            .unwrap_err();
        assert!(matches!(err, ProtocolError::CcvAddressLengthMismatch { index: 1, .. }));
        let err = crate::receipt::compute_ccv_and_executor_hash(&[bytes20(0x11)], &Vec::new()).unwrap_err();
        assert!(matches!(err, ProtocolError::EmptyExecutorAddress));
    }

    #[test]
    fn message_id_is_keccak_of_encoding() {
        // Independently confirm against alloy's keccak rather than only the Go vector.
        let msg = golden_message(None);
        let expected = keccak256(msg.encode());
        assert_eq!(msg.message_id(), expected);
        assert_eq!(alloy_hex::encode(expected), "8527b04a622efd89664aeaa2269dcdf2f4f46898e2776aa144f874bace7be211");
    }
}
