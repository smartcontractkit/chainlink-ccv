package stellar

// TODO: move this into a package outside of the devenv, chainlink-stellar?

import (
	"fmt"
	"sort"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// OnRampStaticConfig represents the static configuration for the OnRamp contract.
type OnRampStaticConfig struct {
	ChainSelector         uint64
	TokenAdminRegistry    string // Contract address (C...)
	RMNRemote             string // Contract address (C...)
	MaxUsdCentsPerMessage uint32
}

// OnRampDynamicConfig represents the dynamic configuration for the OnRamp contract.
type OnRampDynamicConfig struct {
	FeeQuoter     string // Contract address (C...)
	FeeAggregator string // Contract address (C...)
}

// DestChainConfig represents the configuration for a destination chain.
type DestChainConfig struct {
	Router               string   // Contract address (C...) or account (G...)
	MessageNumber        uint64   // Last used message number
	AddressBytesLength   uint32   // e.g., 20 for EVM, 32 for Stellar
	TokenReceiverAllowed bool     // Whether token receiver is allowed
	MessageNetworkFeeUsd uint32   // Network fee in USD cents for messages
	TokenNetworkFeeUsd   uint32   // Network fee in USD cents for tokens
	BaseExecutionGasCost uint32   // Base gas cost for execution
	DefaultExecutor      string   // Executor address
	LaneMandatedCCVs     []string // Lane-mandated CCV addresses
	DefaultCCVs          []string // Default CCV addresses
	OffRamp              []byte   // OffRamp address bytes on destination
}

// DestChainConfigArgs represents arguments for configuring a destination chain.
type DestChainConfigArgs struct {
	DestChainSelector    uint64
	Router               string
	AddressBytesLength   uint32
	TokenReceiverAllowed bool
	MessageNetworkFeeUsd uint32
	TokenNetworkFeeUsd   uint32
	BaseExecutionGasCost uint32
	DefaultExecutor      string
	LaneMandatedCCVs     []string
	DefaultCCVs          []string
	OffRamp              []byte
}

// StellarToAnyMessage represents a CCIP message from Stellar.
type StellarToAnyMessage struct {
	Receiver     []byte        // Raw receiver address bytes
	Data         []byte        // Arbitrary data payload
	TokenAmounts []TokenAmount // Token amounts to transfer
	FeeToken     string        // Fee token address
	ExtraArgs    []byte        // Extra arguments
}

// TokenAmount represents a token amount for transfers.
type TokenAmount struct {
	Token  string // Token contract address
	Amount int64  // Amount to transfer (i128 in contract, int64 for Go simplicity)
}

// MessageSentResult contains the result of sending a CCIP message.
type MessageSentResult struct {
	MessageID      [32]byte
	SequenceNumber uint64
	Ledger         uint32
	TxHash         string
}

// CCIPMessageSentEvent represents the event emitted by the OnRamp when a message is sent.
type CCIPMessageSentEvent struct {
	DestChainSelector     uint64
	SequenceNumber        uint64
	Sender                string
	MessageID             [32]byte
	FeeToken              string
	TokenAmountBeforeFees int64
	EncodedMessage        []byte
	Ledger                uint32
	TxHash                string
}

// ToScVal converts OnRampStaticConfig to an xdr.ScVal for contract calls.
func (c *OnRampStaticConfig) ToScVal() (xdr.ScVal, error) {
	return buildStructScVal(map[string]xdr.ScVal{
		"chain_selector":            uint64ToScVal(c.ChainSelector),
		"token_admin_registry":      addressToScVal(c.TokenAdminRegistry),
		"rmn_remote":                addressToScVal(c.RMNRemote),
		"max_usd_cents_per_message": uint32ToScVal(c.MaxUsdCentsPerMessage),
	})
}

// ToScVal converts OnRampDynamicConfig to an xdr.ScVal for contract calls.
func (c *OnRampDynamicConfig) ToScVal() (xdr.ScVal, error) {
	return buildStructScVal(map[string]xdr.ScVal{
		"fee_quoter":     addressToScVal(c.FeeQuoter),
		"fee_aggregator": addressToScVal(c.FeeAggregator),
	})
}

// ToScVal converts DestChainConfigArgs to an xdr.ScVal for contract calls.
func (c *DestChainConfigArgs) ToScVal() (xdr.ScVal, error) {
	// Convert CCV lists to ScVal vectors
	laneMandatedScVals := make([]xdr.ScVal, len(c.LaneMandatedCCVs))
	for i, addr := range c.LaneMandatedCCVs {
		laneMandatedScVals[i] = addressToScVal(addr)
	}

	defaultCCVScVals := make([]xdr.ScVal, len(c.DefaultCCVs))
	for i, addr := range c.DefaultCCVs {
		defaultCCVScVals[i] = addressToScVal(addr)
	}

	return buildStructScVal(map[string]xdr.ScVal{
		"dest_chain_selector":           uint64ToScVal(c.DestChainSelector),
		"router":                        addressToScVal(c.Router),
		"address_bytes_length":          uint32ToScVal(c.AddressBytesLength),
		"token_receiver_allowed":        boolToScVal(c.TokenReceiverAllowed),
		"message_network_fee_usd_cents": uint32ToScVal(c.MessageNetworkFeeUsd),
		"token_network_fee_usd_cents":   uint32ToScVal(c.TokenNetworkFeeUsd),
		"base_execution_gas_cost":       uint32ToScVal(c.BaseExecutionGasCost),
		"default_executor":              addressToScVal(c.DefaultExecutor),
		"lane_mandated_ccvs":            vecToScVal(laneMandatedScVals),
		"default_ccvs":                  vecToScVal(defaultCCVScVals),
		"off_ramp":                      bytesToScVal(c.OffRamp),
	})
}

// ToScVal converts StellarToAnyMessage to an xdr.ScVal for contract calls.
func (m *StellarToAnyMessage) ToScVal() (xdr.ScVal, error) {
	tokenAmountScVals := make([]xdr.ScVal, len(m.TokenAmounts))
	for i, ta := range m.TokenAmounts {
		taScVal, err := buildStructScVal(map[string]xdr.ScVal{
			"token":  addressToScVal(ta.Token),
			"amount": i128ToScVal(ta.Amount),
		})
		if err != nil {
			return xdr.ScVal{}, err
		}
		tokenAmountScVals[i] = taScVal
	}

	return buildStructScVal(map[string]xdr.ScVal{
		"receiver":      bytesToScVal(m.Receiver),
		"data":          bytesToScVal(m.Data),
		"token_amounts": vecToScVal(tokenAmountScVals),
		"fee_token":     addressToScVal(m.FeeToken),
		"extra_args":    bytesToScVal(m.ExtraArgs),
	})
}

// Helper functions for ScVal conversions

func uint64ToScVal(v uint64) xdr.ScVal {
	xdrU64 := xdr.Uint64(v)
	return xdr.ScVal{
		Type: xdr.ScValTypeScvU64,
		U64:  &xdrU64,
	}
}

func uint32ToScVal(v uint32) xdr.ScVal {
	xdrU32 := xdr.Uint32(v)
	return xdr.ScVal{
		Type: xdr.ScValTypeScvU32,
		U32:  &xdrU32,
	}
}

func boolToScVal(v bool) xdr.ScVal {
	return xdr.ScVal{
		Type: xdr.ScValTypeScvBool,
		B:    &v,
	}
}

func i128ToScVal(v int64) xdr.ScVal {
	var hi int64
	if v < 0 {
		hi = -1 // Sign extend for negative numbers
	}
	lo := uint64(v)
	parts := xdr.Int128Parts{
		Hi: xdr.Int64(hi),
		Lo: xdr.Uint64(lo),
	}
	return xdr.ScVal{
		Type: xdr.ScValTypeScvI128,
		I128: &parts,
	}
}

func bytesToScVal(b []byte) xdr.ScVal {
	bytes := xdr.ScBytes(b)
	return xdr.ScVal{
		Type:  xdr.ScValTypeScvBytes,
		Bytes: &bytes,
	}
}

func addressToScVal(addr string) xdr.ScVal {
	scAddr := parseAddress(addr)
	return xdr.ScVal{
		Type:    xdr.ScValTypeScvAddress,
		Address: scAddr,
	}
}

func vecToScVal(items []xdr.ScVal) xdr.ScVal {
	scVec := xdr.ScVec(items)
	// ScVal.Vec field is **ScVec, so we need to allocate and take address
	vecPtr := &scVec
	return xdr.ScVal{
		Type: xdr.ScValTypeScvVec,
		Vec:  &vecPtr,
	}
}

func symbolToScVal(sym string) xdr.ScVal {
	scSym := xdr.ScSymbol(sym)
	return xdr.ScVal{
		Type: xdr.ScValTypeScvSymbol,
		Sym:  &scSym,
	}
}

func buildStructScVal(fields map[string]xdr.ScVal) (xdr.ScVal, error) {
	// Soroban requires ScMap keys to be sorted lexicographically
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	entries := make([]xdr.ScMapEntry, 0, len(fields))
	for _, k := range keys {
		v := fields[k]
		sym := xdr.ScSymbol(k)
		entries = append(entries, xdr.ScMapEntry{
			Key: xdr.ScVal{
				Type: xdr.ScValTypeScvSymbol,
				Sym:  &sym,
			},
			Val: v,
		})
	}
	scMap := xdr.ScMap(entries)
	// ScVal.Map field is **ScMap, so we need to allocate and take address
	mapPtr := &scMap
	return xdr.ScVal{
		Type: xdr.ScValTypeScvMap,
		Map:  &mapPtr,
	}, nil
}

// parseAddress parses a Stellar address string (G... or C...) into an xdr.ScAddress.
func parseAddress(addr string) *xdr.ScAddress {
	if len(addr) == 0 {
		return nil
	}

	// Handle contract addresses (C...)
	if addr[0] == 'C' {
		decoded, err := strkey.Decode(strkey.VersionByteContract, addr)
		if err != nil {
			return nil
		}
		// Build ScAddress for contract using MakeScAddress helper if available,
		// or construct manually. The ContractId field type varies by SDK version.
		return buildContractScAddress(decoded)
	}

	// Handle account addresses (G...)
	if addr[0] == 'G' {
		decoded, err := strkey.Decode(strkey.VersionByteAccountID, addr)
		if err != nil {
			return nil
		}
		var pubKey xdr.Uint256
		copy(pubKey[:], decoded)
		accountID := xdr.AccountId{
			Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
			Ed25519: &pubKey,
		}
		return &xdr.ScAddress{
			Type:      xdr.ScAddressTypeScAddressTypeAccount,
			AccountId: &accountID,
		}
	}

	return nil
}

// addressFromScVal extracts a strkey address from an xdr.ScVal.
func addressFromScVal(val xdr.ScVal) (string, error) {
	addr, ok := val.GetAddress()
	if !ok {
		return "", fmt.Errorf("not an address type: %v", val.Type)
	}

	switch addr.Type {
	case xdr.ScAddressTypeScAddressTypeAccount:
		accountID := addr.MustAccountId()
		pubKey := accountID.Ed25519
		if pubKey == nil {
			return "", fmt.Errorf("account ID has no Ed25519 key")
		}
		return strkey.Encode(strkey.VersionByteAccountID, (*pubKey)[:])
	case xdr.ScAddressTypeScAddressTypeContract:
		contractID := addr.MustContractId()
		return strkey.Encode(strkey.VersionByteContract, contractID[:])
	default:
		return "", fmt.Errorf("unsupported address type: %s", addr.Type)
	}
}

// uint64FromScVal extracts a uint64 from an xdr.ScVal.
func uint64FromScVal(val xdr.ScVal) (uint64, error) {
	u64, ok := val.GetU64()
	if !ok {
		return 0, fmt.Errorf("not a u64 type: %v", val.Type)
	}
	return uint64(u64), nil
}

// bytes32FromScVal extracts a [32]byte from an xdr.ScVal containing BytesN<32>.
func bytes32FromScVal(val xdr.ScVal) ([32]byte, error) {
	bytes, ok := val.GetBytes()
	if !ok {
		return [32]byte{}, fmt.Errorf("not a bytes type: %v", val.Type)
	}
	if len(bytes) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(bytes))
	}
	var result [32]byte
	copy(result[:], bytes)
	return result, nil
}

// i128FromScVal extracts an int64 from an xdr.ScVal containing i128.
// Note: This truncates to int64 for simplicity.
func i128FromScVal(val xdr.ScVal) (int64, error) {
	i128, ok := val.GetI128()
	if !ok {
		return 0, fmt.Errorf("not an i128 type: %v", val.Type)
	}
	// For simplicity, assume the value fits in int64
	return int64(i128.Lo), nil
}

// buildContractScAddress creates an ScAddress for a contract from raw bytes.
// Uses XDR marshaling to properly construct the address with correct types.
func buildContractScAddress(contractIDBytes []byte) *xdr.ScAddress {
	if len(contractIDBytes) != 32 {
		return nil
	}
	// Construct via XDR encoding to handle SDK type requirements
	// ScAddress union: type (4 bytes) + data (32 bytes for contract)
	xdrBytes := make([]byte, 0, 36)
	// Type discriminant for contract: ScAddressTypeScAddressTypeContract = 1
	xdrBytes = append(xdrBytes, 0, 0, 0, 1) // Big-endian uint32
	xdrBytes = append(xdrBytes, contractIDBytes...)

	var addr xdr.ScAddress
	if err := addr.UnmarshalBinary(xdrBytes); err != nil {
		return nil
	}
	return &addr
}
