package destinationreader

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-evm/pkg/client"
)

/*
NOTE: Full unit testing of GetCCVSForMessage, GetMessageExecutionState, and GetRMNCursedSubjects
requires mocking the generated EVM contract bindings (offramp.OffRampCaller and rmn_remote.RMNRemoteCaller).

Since these are concrete structs from generated code rather than interfaces, they cannot be easily mocked
without either:
1. Modifying the source code to use interface wrappers
2. Using integration tests with actual contract deployments
3. Using more advanced mocking techniques (e.g., gomock with code generation)

We have a ticket to abstract the business logic away from the code that calls the contract methods. This test will be updated when that ticket is complete.
https://smartcontract-it.atlassian.net/browse/CCIP-8168.
*/

// dummyChainClient is a minimal mock that satisfies client.Client interface.
// Used only for validation tests where we don't actually call contract methods.
type dummyChainClient struct {
	mock.Mock
	client.Client
}

func (d *dummyChainClient) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	return []byte{0x01}, nil // Return non-empty code to pass contract existence checks
}

func (d *dummyChainClient) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	return nil, nil
}

// TestNewEvmDestinationReader_ParameterValidation tests that NewEvmDestinationReader
// properly validates input parameters.
// Note: The validation function checks if parameters are nil (not empty), so it only catches
// missing pointers/interfaces, not empty strings or zero values.
func TestNewEvmDestinationReader_ParameterValidation(t *testing.T) {
	testCases := []struct {
		name          string
		params        Params
		expectedError string
	}{
		{
			name: "missing logger",
			params: Params{
				Lggr:             nil,
				ChainSelector:    protocol.ChainSelector(1),
				ChainClient:      &dummyChainClient{},
				OfframpAddress:   "0x1111111111111111111111111111111111111111",
				RmnRemoteAddress: "0x2222222222222222222222222222222222222222",
				CacheExpiry:      5 * time.Minute,
			},
			expectedError: "logger is not set",
		},
		{
			name: "missing chain client",
			params: Params{
				Lggr:             logger.Test(t),
				ChainSelector:    protocol.ChainSelector(1),
				ChainClient:      nil,
				OfframpAddress:   "0x1111111111111111111111111111111111111111",
				RmnRemoteAddress: "0x2222222222222222222222222222222222222222",
				CacheExpiry:      5 * time.Minute,
			},
			expectedError: "chainClient is not set",
		},
		{
			name: "multiple missing parameters",
			params: Params{
				Lggr:             nil,
				ChainSelector:    protocol.ChainSelector(1),
				ChainClient:      nil,
				OfframpAddress:   "0x1111111111111111111111111111111111111111",
				RmnRemoteAddress: "0x2222222222222222222222222222222222222222",
				CacheExpiry:      5 * time.Minute,
			},
			expectedError: "is not set",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader, err := NewEvmDestinationReader(tc.params)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedError)
			assert.Nil(t, reader)
		})
	}
}

// TestVerifierQuorumCacheKey tests the cache key structure used for CCV info caching.
func TestVerifierQuorumCacheKey(t *testing.T) {
	testCases := []struct {
		name     string
		key1     verifierQuorumCacheKey
		key2     verifierQuorumCacheKey
		shouldBe string
	}{
		{
			name: "different source chain selectors produce different keys",
			key1: verifierQuorumCacheKey{
				sourceChainSelector:  protocol.ChainSelector(1),
				receiverAddress:      "0x123",
				tokenTransferAddress: [20]byte{},
			},
			key2: verifierQuorumCacheKey{
				sourceChainSelector:  protocol.ChainSelector(2),
				receiverAddress:      "0x123",
				tokenTransferAddress: [20]byte{},
			},
			shouldBe: "different",
		},
		{
			name: "different receiver addresses produce different keys",
			key1: verifierQuorumCacheKey{
				sourceChainSelector:  protocol.ChainSelector(1),
				receiverAddress:      "0x123",
				tokenTransferAddress: [20]byte{},
			},
			key2: verifierQuorumCacheKey{
				sourceChainSelector:  protocol.ChainSelector(1),
				receiverAddress:      "0x456",
				tokenTransferAddress: [20]byte{},
			},
			shouldBe: "different",
		},
		{
			name: "different token transfer addresses produce different keys",
			key1: verifierQuorumCacheKey{
				sourceChainSelector:  protocol.ChainSelector(1),
				receiverAddress:      "0x123",
				tokenTransferAddress: [20]byte{1},
			},
			key2: verifierQuorumCacheKey{
				sourceChainSelector:  protocol.ChainSelector(1),
				receiverAddress:      "0x123",
				tokenTransferAddress: [20]byte{2},
			},
			shouldBe: "different",
		},
		{
			name: "identical keys are equal",
			key1: verifierQuorumCacheKey{
				sourceChainSelector:  protocol.ChainSelector(1),
				receiverAddress:      "0x123",
				tokenTransferAddress: [20]byte{1},
			},
			key2: verifierQuorumCacheKey{
				sourceChainSelector:  protocol.ChainSelector(1),
				receiverAddress:      "0x123",
				tokenTransferAddress: [20]byte{1},
			},
			shouldBe: "equal",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldBe == "different" {
				assert.NotEqual(t, tc.key1, tc.key2, "cache keys should be different")
			} else {
				assert.Equal(t, tc.key1, tc.key2, "cache keys should be equal")
			}
		})
	}
}

// TestVerifierQuorumCacheMaxEntries verifies the cache size constant.
func TestVerifierQuorumCacheMaxEntries(t *testing.T) {
	// Ensure the cache max entries constant is set to a reasonable value
	assert.Equal(t, 1000, VerifierQuorumCacheMaxEntries, "cache max entries should be 1000")
	assert.Greater(t, VerifierQuorumCacheMaxEntries, 0, "cache max entries must be positive")
}

/*
NOTE: Full unit testing of GetCCVSForMessage, GetMessageExecutionState, and GetRMNCursedSubjects
requires mocking the generated EVM contract bindings (offramp.OffRampCaller and rmn_remote.RMNRemoteCaller).

Since these are concrete structs from generated code rather than interfaces, they cannot be easily mocked
without either:
1. Modifying the source code to use interface wrappers
2. Using integration tests with actual contract deployments
3. Using more advanced mocking techniques (e.g., gomock with code generation)

The methods implement the following behavior (documented for reference):

GetCCVSForMessage:
- Extracts token transfer address from message if present
- Checks cache for existing CCV info using (sourceChainSelector, receiverAddress, tokenTransferAddress) as key
- On cache miss, calls offramp.GetCCVsForMessage with encoded message
- Converts returned addresses to protocol.UnknownAddress format
- Caches the result with configured expiry time
- Returns CCVAddressInfo with RequiredCCVs, OptionalCCVs, and OptionalThreshold

GetMessageExecutionState:
- Calls offramp.GetExecutionState with message details
- Returns one of: UNTOUCHED, IN_PROGRESS, SUCCESS, or FAILURE
- Used to determine if a message has already been executed on-chain

GetRMNCursedSubjects:
- Delegates to rmnremotereader.EVMReadRMNCursedSubjects
- Returns list of cursed chain selectors or global curse indicator
- Used for curse checking before message execution

For production testing, consider:
- Integration tests with test network deployments
- Creating interface wrappers for the generated bindings
- Using contract simulation frameworks
*/
