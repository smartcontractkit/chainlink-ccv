package executor

import (
	cciptypes "github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
	"math/big"
)

type AbstractAggregatedReport struct {
	Message Any2AnyVerifierMessage
	CCVS    []string
	Proofs  []byte
}

// ContractAddresses is a map of contract names across all chain selectors and their address.
// Currently only one contract per chain per name is supported.
type ContractAddresses map[string]map[uint64]string

// MessageWithCCVData is a struct that represents the data in between the indexer and executor
type MessageWithCCVData struct {
	Message        Any2AnyVerifierMessage
	CCVData        []CCVData
	ReadyTimestamp uint64
}

type UnknownAddress []byte

type CCVData struct {
	MessageID             cciptypes.Bytes32       `json:"message_id"`
	SequenceNumber        cciptypes.SeqNum        `json:"sequence_number"`
	SourceChainSelector   cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector     cciptypes.ChainSelector `json:"dest_chain_selector"`
	SourceVerifierAddress UnknownAddress          `json:"source_verifier_address"`
	DestVerifierAddress   UnknownAddress          `json:"dest_verifier_address"`
	CCVData               []byte                  `json:"ccv_data"`  // The actual proof/signature
	BlobData              []byte                  `json:"blob_data"` // Additional verifier-specific data
	Timestamp             int64                   `json:"timestamp"` // Unix timestamp when verification completed (in microseconds)
	Message               Any2AnyVerifierMessage  `json:"message"`   // Complete message event being verified
}

// Any2AnyVerifierMessage represents a chain-agnostic CCIP message
type Any2AnyVerifierMessage struct {
	Header           MessageHeader  `json:"header"`
	Sender           UnknownAddress `json:"sender"`
	OnRampAddress    UnknownAddress `json:"onramp_address"` // CCVProxy address
	Data             []byte         `json:"data"`
	Receiver         UnknownAddress `json:"receiver"`
	FeeToken         UnknownAddress `json:"fee_token"`
	FeeTokenAmount   *big.Int       `json:"fee_token_amount"`
	FeeValueJuels    *big.Int       `json:"fee_value_juels"`
	TokenTransfer    TokenTransfer  `json:"token_transfer"`
	VerifierReceipts []Receipt      `json:"verifier_receipts"`
	ExecutorReceipt  *Receipt       `json:"executor_receipt"`
	TokenReceipt     *Receipt       `json:"token_receipt"`
	ExtraArgs        []byte         `json:"extra_args"`
}

// MessageHeader represents the common header for all CCIP messages
type MessageHeader struct {
	MessageID           cciptypes.Bytes32       `json:"message_id"`
	SourceChainSelector cciptypes.ChainSelector `json:"source_chain_selector"`
	DestChainSelector   cciptypes.ChainSelector `json:"dest_chain_selector"`
	SequenceNumber      cciptypes.SeqNum        `json:"sequence_number"`
}

// TokenTransfer represents a token transfer in the CCIP protocol
type TokenTransfer struct {
	SourceTokenAddress UnknownAddress `json:"source_token_address"`
	DestTokenAddress   UnknownAddress `json:"dest_token_address"`
	ExtraData          []byte         `json:"extra_data"`
	Amount             *big.Int       `json:"amount"`
}

// Receipt represents return data from a verifier or executor
type Receipt struct {
	Issuer            UnknownAddress `json:"issuer"`
	FeeTokenAmount    *big.Int       `json:"fee_token_amount"`
	DestGasLimit      uint64         `json:"dest_gas_limit"`
	DestBytesOverhead uint32         `json:"dest_bytes_overhead"`
	ExtraArgs         []byte         `json:"extra_args"`
}
