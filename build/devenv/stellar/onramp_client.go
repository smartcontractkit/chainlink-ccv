package stellar

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	"github.com/stellar/go-stellar-sdk/keypair"
	protocolrpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// OnRampClient provides methods to interact with the Stellar OnRamp contract.
type OnRampClient struct {
	deployer   *Deployer
	contractID string
}

// NewOnRampClient creates a new OnRampClient.
func NewOnRampClient(rpcClient *rpcclient.Client, networkPassphrase string, signer *keypair.Full, contractID string) *OnRampClient {
	return &OnRampClient{
		deployer:   NewDeployer(rpcClient, networkPassphrase, signer),
		contractID: contractID,
	}
}

// DeployOnRamp deploys the OnRamp contract and returns the contract ID.
func DeployOnRamp(ctx context.Context, rpcClient *rpcclient.Client, networkPassphrase string, signer *keypair.Full, wasmPath string) (string, error) {
	deployer := NewDeployer(rpcClient, networkPassphrase, signer)

	// Generate a deterministic salt based on the deployer address and "onramp"
	salt := GenerateDeterministicSalt(signer.Address(), "onramp")

	return deployer.DeployContract(ctx, wasmPath, salt)
}

// Initialize initializes the OnRamp contract with the given configuration.
func (c *OnRampClient) Initialize(ctx context.Context, owner string, staticConfig OnRampStaticConfig, dynamicConfig OnRampDynamicConfig) error {
	// Convert configs to ScVal
	ownerScVal := addressToScVal(owner)

	staticScVal, err := staticConfig.ToScVal()
	if err != nil {
		return fmt.Errorf("failed to convert static config: %w", err)
	}

	dynamicScVal, err := dynamicConfig.ToScVal()
	if err != nil {
		return fmt.Errorf("failed to convert dynamic config: %w", err)
	}

	// Invoke initialize function
	_, err = c.deployer.InvokeContract(ctx, c.contractID, "initialize", []xdr.ScVal{
		ownerScVal,
		staticScVal,
		dynamicScVal,
	})
	if err != nil {
		return fmt.Errorf("failed to invoke initialize: %w", err)
	}

	return nil
}

// ApplyDestChainConfigUpdates applies destination chain configuration updates.
func (c *OnRampClient) ApplyDestChainConfigUpdates(ctx context.Context, configs []DestChainConfigArgs) error {
	// Convert configs to ScVal vector
	configScVals := make([]xdr.ScVal, len(configs))
	for i, config := range configs {
		scVal, err := config.ToScVal()
		if err != nil {
			return fmt.Errorf("failed to convert dest chain config %d: %w", i, err)
		}
		configScVals[i] = scVal
	}

	// Invoke apply_dest_chain_config_updates function
	_, err := c.deployer.InvokeContract(ctx, c.contractID, "apply_dest_chain_config_updates", []xdr.ScVal{
		vecToScVal(configScVals),
	})
	if err != nil {
		return fmt.Errorf("failed to invoke apply_dest_chain_config_updates: %w", err)
	}

	return nil
}

// ForwardFromRouter sends a CCIP message through the OnRamp.
// This is the core function for sending cross-chain messages.
func (c *OnRampClient) ForwardFromRouter(ctx context.Context, destChainSelector uint64, message StellarToAnyMessage, feeTokenAmount int64, originalSender string) (*MessageSentResult, error) {
	// Convert message to ScVal
	messageScVal, err := message.ToScVal()
	if err != nil {
		return nil, fmt.Errorf("failed to convert message: %w", err)
	}

	// Invoke forward_from_router function
	result, err := c.deployer.InvokeContract(ctx, c.contractID, "forward_from_router", []xdr.ScVal{
		uint64ToScVal(destChainSelector),
		messageScVal,
		i128ToScVal(feeTokenAmount),
		addressToScVal(originalSender),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to invoke forward_from_router: %w", err)
	}

	// Extract message ID from result (should be BytesN<32>)
	if result == nil {
		return nil, fmt.Errorf("no return value from forward_from_router")
	}

	messageID, err := bytes32FromScVal(*result)
	if err != nil {
		return nil, fmt.Errorf("failed to extract message ID: %w", err)
	}

	return &MessageSentResult{
		MessageID: messageID,
	}, nil
}

// GetExpectedNextMessageNumber returns the expected next sequence number for messages to a destination chain.
func (c *OnRampClient) GetExpectedNextMessageNumber(ctx context.Context, destChainSelector uint64) (uint64, error) {
	// Simulate the call (read-only)
	result, err := c.deployer.SimulateContract(ctx, c.contractID, "get_expected_next_message_number", []xdr.ScVal{
		uint64ToScVal(destChainSelector),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to simulate get_expected_next_message_number: %w", err)
	}

	if result == nil {
		return 0, fmt.Errorf("no return value")
	}

	seqNo, err := uint64FromScVal(*result)
	if err != nil {
		return 0, fmt.Errorf("failed to extract sequence number: %w", err)
	}

	return seqNo, nil
}

// GetStaticConfig returns the static configuration of the OnRamp.
func (c *OnRampClient) GetStaticConfig(ctx context.Context) (*OnRampStaticConfig, error) {
	result, err := c.deployer.SimulateContract(ctx, c.contractID, "get_static_config", []xdr.ScVal{})
	if err != nil {
		return nil, fmt.Errorf("failed to simulate get_static_config: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("no return value")
	}

	return parseStaticConfig(*result)
}

// GetDynamicConfig returns the dynamic configuration of the OnRamp.
func (c *OnRampClient) GetDynamicConfig(ctx context.Context) (*OnRampDynamicConfig, error) {
	result, err := c.deployer.SimulateContract(ctx, c.contractID, "get_dynamic_config", []xdr.ScVal{})
	if err != nil {
		return nil, fmt.Errorf("failed to simulate get_dynamic_config: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("no return value")
	}

	return parseDynamicConfig(*result)
}

// GetDestChainConfig returns the configuration for a specific destination chain.
func (c *OnRampClient) GetDestChainConfig(ctx context.Context, destChainSelector uint64) (*DestChainConfig, error) {
	result, err := c.deployer.SimulateContract(ctx, c.contractID, "get_dest_chain_config", []xdr.ScVal{
		uint64ToScVal(destChainSelector),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to simulate get_dest_chain_config: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("no return value")
	}

	return parseDestChainConfig(*result)
}

// WaitForMessageSentEvent waits for a CCIPMessageSent event with the given sequence number.
func (c *OnRampClient) WaitForMessageSentEvent(ctx context.Context, destChainSelector uint64, sequenceNumber uint64, timeout time.Duration) (*CCIPMessageSentEvent, error) {
	startTime := time.Now()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Get the starting ledger
	latestLedger, err := c.deployer.rpcClient.GetLatestLedger(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest ledger: %w", err)
	}
	startLedger := uint32(latestLedger.Sequence) - 100 // Look back a bit

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Since(startTime) > timeout {
				return nil, fmt.Errorf("timeout waiting for message sent event")
			}

			// Poll for events
			event, err := c.findMessageSentEvent(ctx, startLedger, destChainSelector, sequenceNumber)
			if err != nil {
				continue // Retry on error
			}
			if event != nil {
				return event, nil
			}
		}
	}
}

// findMessageSentEvent searches for a specific CCIPMessageSent event.
func (c *OnRampClient) findMessageSentEvent(ctx context.Context, startLedger uint32, destChainSelector uint64, sequenceNumber uint64) (*CCIPMessageSentEvent, error) {
	events, err := c.deployer.GetEvents(ctx, c.contractID, startLedger, []string{"onramp_1_7_CCIPMessageSent"})
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		parsed, err := parseCCIPMessageSentEvent(event)
		if err != nil {
			continue
		}

		if parsed.DestChainSelector == destChainSelector && parsed.SequenceNumber == sequenceNumber {
			return parsed, nil
		}
	}

	return nil, nil // Not found yet
}

// GetAllMessageSentEvents returns all CCIPMessageSent events from a starting ledger.
func (c *OnRampClient) GetAllMessageSentEvents(ctx context.Context, startLedger uint32) ([]*CCIPMessageSentEvent, error) {
	events, err := c.deployer.GetEvents(ctx, c.contractID, startLedger, []string{"onramp_1_7_CCIPMessageSent"})
	if err != nil {
		return nil, err
	}

	result := make([]*CCIPMessageSentEvent, 0, len(events))
	for _, event := range events {
		parsed, err := parseCCIPMessageSentEvent(event)
		if err != nil {
			continue
		}
		result = append(result, parsed)
	}

	return result, nil
}

// ContractID returns the contract ID of this OnRamp client.
func (c *OnRampClient) ContractID() string {
	return c.contractID
}

// Helper functions for parsing contract responses

func parseStaticConfig(val xdr.ScVal) (*OnRampStaticConfig, error) {
	scMap, ok := val.GetMap()
	if !ok || scMap == nil {
		return nil, fmt.Errorf("not a map type")
	}

	config := &OnRampStaticConfig{}
	for _, entry := range *scMap {
		key, ok := entry.Key.GetSym()
		if !ok {
			continue
		}

		switch string(key) {
		case "chain_selector":
			v, err := uint64FromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			config.ChainSelector = v
		case "token_admin_registry":
			v, err := addressFromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			config.TokenAdminRegistry = v
		case "rmn_remote":
			v, err := addressFromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			config.RMNRemote = v
		case "max_usd_cents_per_message":
			u32, ok := entry.Val.GetU32()
			if !ok {
				return nil, fmt.Errorf("max_usd_cents_per_message is not u32")
			}
			config.MaxUsdCentsPerMessage = uint32(u32)
		}
	}

	return config, nil
}

func parseDynamicConfig(val xdr.ScVal) (*OnRampDynamicConfig, error) {
	scMap, ok := val.GetMap()
	if !ok || scMap == nil {
		return nil, fmt.Errorf("not a map type")
	}

	config := &OnRampDynamicConfig{}
	for _, entry := range *scMap {
		key, ok := entry.Key.GetSym()
		if !ok {
			continue
		}

		switch string(key) {
		case "fee_quoter":
			v, err := addressFromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			config.FeeQuoter = v
		case "fee_aggregator":
			v, err := addressFromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			config.FeeAggregator = v
		}
	}

	return config, nil
}

func parseDestChainConfig(val xdr.ScVal) (*DestChainConfig, error) {
	scMap, ok := val.GetMap()
	if !ok || scMap == nil {
		return nil, fmt.Errorf("not a map type")
	}

	config := &DestChainConfig{}
	for _, entry := range *scMap {
		key, ok := entry.Key.GetSym()
		if !ok {
			continue
		}

		switch string(key) {
		case "router":
			v, err := addressFromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			config.Router = v
		case "message_number":
			v, err := uint64FromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			config.MessageNumber = v
		case "address_bytes_length":
			u32, ok := entry.Val.GetU32()
			if !ok {
				return nil, fmt.Errorf("address_bytes_length is not u32")
			}
			config.AddressBytesLength = uint32(u32)
		case "base_execution_gas_cost":
			u32, ok := entry.Val.GetU32()
			if !ok {
				return nil, fmt.Errorf("base_execution_gas_cost is not u32")
			}
			config.BaseExecutionGasCost = uint32(u32)
		}
	}

	return config, nil
}

func parseCCIPMessageSentEvent(event protocolrpc.EventInfo) (*CCIPMessageSentEvent, error) {
	// Parse the event value which contains the event data as a struct
	var eventVal xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(event.ValueXDR, &eventVal); err != nil {
		return nil, fmt.Errorf("failed to decode event value: %w", err)
	}

	scMap, ok := eventVal.GetMap()
	if !ok || scMap == nil {
		return nil, fmt.Errorf("event value is not a map")
	}

	parsed := &CCIPMessageSentEvent{
		Ledger: uint32(event.Ledger),
		TxHash: event.TransactionHash,
	}

	for _, entry := range *scMap {
		key, ok := entry.Key.GetSym()
		if !ok {
			continue
		}

		switch string(key) {
		case "dest_chain_selector":
			v, err := uint64FromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			parsed.DestChainSelector = v
		case "sequence_number":
			v, err := uint64FromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			parsed.SequenceNumber = v
		case "sender":
			v, err := addressFromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			parsed.Sender = v
		case "message_id":
			v, err := bytes32FromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			parsed.MessageID = v
		case "fee_token":
			v, err := addressFromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			parsed.FeeToken = v
		case "token_amount_before_fees":
			v, err := i128FromScVal(entry.Val)
			if err != nil {
				return nil, err
			}
			parsed.TokenAmountBeforeFees = v
		case "encoded_message":
			bytes, ok := entry.Val.GetBytes()
			if !ok {
				return nil, fmt.Errorf("encoded_message is not bytes")
			}
			parsed.EncodedMessage = []byte(bytes)
		}
	}

	return parsed, nil
}

// DeployCCVMock deploys a mock CCV contract for testing.
func DeployCCVMock(ctx context.Context, rpcClient *rpcclient.Client, networkPassphrase string, signer *keypair.Full, wasmPath string, index int) (string, error) {
	deployer := NewDeployer(rpcClient, networkPassphrase, signer)

	salt := GenerateDeterministicSalt(signer.Address(), fmt.Sprintf("ccv-%d", index))

	return deployer.DeployContract(ctx, wasmPath, salt)
}

// DeployFeeQuoterMock deploys a mock FeeQuoter contract for testing.
func DeployFeeQuoterMock(ctx context.Context, rpcClient *rpcclient.Client, networkPassphrase string, signer *keypair.Full, wasmPath string) (string, error) {
	deployer := NewDeployer(rpcClient, networkPassphrase, signer)

	salt := GenerateDeterministicSalt(signer.Address(), "fee-quoter")

	return deployer.DeployContract(ctx, wasmPath, salt)
}

// GenerateContractAddress generates a deterministic contract address for testing.
// This matches the address that would be generated during deployment with the same salt.
func GenerateContractAddress(networkPassphrase string, deployerAddress string, contractName string) (string, error) {
	salt := GenerateDeterministicSalt(deployerAddress, contractName)

	// Decode deployer address
	deployerBytes, err := strkey.Decode(strkey.VersionByteAccountID, deployerAddress)
	if err != nil {
		return "", fmt.Errorf("failed to decode deployer address: %w", err)
	}

	// Create contract ID preimage
	var deployerPubKey xdr.Uint256
	copy(deployerPubKey[:], deployerBytes)

	preimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeContractId,
		ContractId: &xdr.HashIdPreimageContractId{
			NetworkId: sha256.Sum256([]byte(networkPassphrase)),
			ContractIdPreimage: xdr.ContractIdPreimage{
				Type: xdr.ContractIdPreimageTypeContractIdPreimageFromAddress,
				FromAddress: &xdr.ContractIdPreimageFromAddress{
					Address: xdr.ScAddress{
						Type: xdr.ScAddressTypeScAddressTypeAccount,
						AccountId: &xdr.AccountId{
							Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
							Ed25519: &deployerPubKey,
						},
					},
					Salt: xdr.Uint256(salt),
				},
			},
		},
	}

	// Hash the preimage
	preimageBytes, err := preimage.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal preimage: %w", err)
	}

	contractIDHash := sha256.Sum256(preimageBytes)

	// Encode as strkey contract address
	return strkey.Encode(strkey.VersionByteContract, contractIDHash[:])
}
