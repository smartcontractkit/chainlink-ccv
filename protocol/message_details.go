package protocol

import "math/big"

// MessageDetails contains reader-supplied addresses and decoded event metadata for consumers.
// It is separate from Message: its normalized addresses must never replace the original
// message bytes used to compute message IDs or signatures.
type MessageDetails struct {
	OnRampAddress      UnknownAddress      `json:"on_ramp_address"`
	OffRampAddress     UnknownAddress      `json:"off_ramp_address"`
	Sender             UnknownAddress      `json:"sender"`
	Receiver           UnknownAddress      `json:"receiver"`
	SourcePoolAddress  UnknownAddress      `json:"source_pool_address,omitempty"`
	SourceTokenAddress UnknownAddress      `json:"source_token_address,omitempty"`
	DestTokenAddress   UnknownAddress      `json:"dest_token_address,omitempty"`
	TokenReceiver      UnknownAddress      `json:"token_receiver,omitempty"`
	FeeToken           UnknownAddress      `json:"fee_token,omitempty"`
	FeeTokenAmount     *big.Int            `json:"fee_token_amount,omitempty"`
	Finality           FinalityRequirement `json:"finality"`
}
