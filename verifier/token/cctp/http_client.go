package cctp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
	httputil "github.com/smartcontractkit/chainlink-ccv/verifier/token/http"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	apiVersionV2 = "v2"
	messagesPath = "messages"

	attestationStatusSuccess string = "complete"
	attestationStatusPending string = "pending_confirmations"
)

// HTTPClient defines the interface for fetching CCTP v2 messages via HTTP. At this stage we don't expose or implement
// any CCIP specific logic. It's purely to handle communication with Iris according to Circle's CCTP v2 API spec.
// https://developers.circle.com/api-reference/cctp/all/get-messages-v2
type HTTPClient interface {
	// GetMessages fetches CCTP v2 messages and attestations for the given transaction.
	GetMessages(
		ctx context.Context, sourceChain protocol.ChainSelector, sourceDomainID uint32, transactionHash string,
	) (Messages, error)
}

type HTTPClientImpl struct {
	lggr   logger.Logger
	client httputil.Client
}

// NewHTTPClient creates a new HTTP-based CCTP v2 attestation client.
func NewHTTPClient(
	lggr logger.Logger,
	config CCTPConfig,
) (*HTTPClientImpl, error) {
	client, err := httputil.GetHTTPClient(
		lggr,
		config.AttestationAPI,
		config.AttestationAPIInterval,
		config.AttestationAPITimeout,
		config.AttestationAPICooldown,
	)
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}
	return &HTTPClientImpl{
		lggr:   lggr,
		client: client,
	}, nil
}

// GetMessages fetches CCTP v2 messages and attestations for the given transaction.
func (c *HTTPClientImpl) GetMessages(
	ctx context.Context,
	sourceChain protocol.ChainSelector,
	sourceDomainID uint32,
	transactionHash string,
) (Messages, error) {
	// Validate transaction hash
	if transactionHash == "" {
		return Messages{}, fmt.Errorf("transaction hash cannot be empty")
	}
	if !strings.HasPrefix(transactionHash, "0x") || len(transactionHash) != 66 {
		return Messages{}, fmt.Errorf("invalid transaction hash format: %s", transactionHash)
	}

	path := fmt.Sprintf("%s/%s/%d?transactionHash=%s",
		apiVersionV2, messagesPath, sourceDomainID, url.QueryEscape(transactionHash))
	body, status, err := c.client.Get(ctx, path)
	if err != nil {
		return Messages{},
			fmt.Errorf("http call failed to get CCTPv2 messages for sourceDomainID %d and transactionHash %s, error: %w",
				sourceDomainID, transactionHash, err)
	}

	if status != http.StatusOK {
		c.lggr.Warnw(
			"Non-200 status from Circle API",
			"status", status,
			"path", path,
			"sourceDomainID", sourceDomainID,
			"transactionHash", transactionHash,
			"responseBody", string(body),
		)
		return Messages{}, fmt.Errorf(
			"circle API returned status %d for path %s", status, path)
	}

	result, err := parseResponseBody(body)
	if err != nil {
		return Messages{}, err
	}

	return result, nil
}

// parseResponseBody parses the JSON response from Circle's attestation API
// and returns a Messages struct containing the decoded CCTP v2 messages.
func parseResponseBody(body protocol.ByteSlice) (Messages, error) {
	var messages Messages
	if err := json.Unmarshal(body, &messages); err != nil {
		return Messages{}, fmt.Errorf("failed to decode json: %w", err)
	}
	return messages, nil
}

// Messages represents the response structure from Circle's attestation API,
// containing a list of CCTP v2 messages with their attestations.
// This API response type is documented here:
// https://developers.circle.com/api-reference/cctp/all/get-messages-v2
type Messages struct {
	Messages []Message `json:"messages"`
}

// Message represents a single CCTP v2 message from Circle's attestation API.
// It contains the message data, attestation signature, and decoded message details
// needed for cross-chain USDC transfers.
type Message struct {
	Message        string         `json:"message"`
	EventNonce     string         `json:"eventNonce"`
	Attestation    string         `json:"attestation"`
	DecodedMessage DecodedMessage `json:"decodedMessage"`
	CCTPVersion    any            `json:"cctpVersion"`
	Status         string         `json:"status"`
}

func (m *Message) IsV2() bool {
	switch v := m.CCTPVersion.(type) {
	case int:
		return v == 2
	case int64:
		return v == 2
	case float64: // JSON numbers unmarshal to float64 by default
		return v == 2
	case string:
		version, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return false
		}
		return version == 2
	default:
		return false
	}
}

func (m *Message) IsAttestationComplete() bool {
	return m.Status == attestationStatusSuccess
}

func (m *Message) DecodeAttestation() (protocol.ByteSlice, error) {
	if !m.IsAttestationComplete() {
		return nil, fmt.Errorf("attestation is not complete, status: %s", m.Status)
	}
	attestation, err := protocol.NewByteSliceFromHex(m.Attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation hex: %w", err)
	}
	return attestation, nil
}

// DecodedMessage represents the 'decodedMessage' object within a Message.
type DecodedMessage struct {
	SourceDomain       string             `json:"sourceDomain"`
	DestinationDomain  string             `json:"destinationDomain"`
	Nonce              string             `json:"nonce"`
	Sender             string             `json:"sender"`
	Recipient          string             `json:"recipient"`
	DestinationCaller  string             `json:"destinationCaller"`
	MessageBody        string             `json:"messageBody"`
	DecodedMessageBody DecodedMessageBody `json:"decodedMessageBody"`
	// The following fields are optional.
	MinFinalityThreshold      string `json:"minFinalityThreshold,omitempty"`
	FinalityThresholdExecuted string `json:"finalityThresholdExecuted,omitempty"`
}

// DecodedMessageBody represents the 'decodedMessageBody' object within a DecodedMessage.
type DecodedMessageBody struct {
	BurnToken     string `json:"burnToken"`
	MintRecipient string `json:"mintRecipient"`
	Amount        string `json:"amount"`
	MessageSender string `json:"messageSender"`
	// The following fields are optional.
	MaxFee          string `json:"maxFee,omitempty"`
	FeeExecuted     string `json:"feeExecuted,omitempty"`
	ExpirationBlock string `json:"expirationBlock,omitempty"`
	HookData        string `json:"hookData,omitempty"`
}
