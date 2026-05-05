package messagerules

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

type RuleType string

const (
	RuleTypeChain RuleType = "Chain"
	RuleTypeLane  RuleType = "Lane"
	RuleTypeToken RuleType = "Token"
)

type Rule struct {
	ID        string
	Type      RuleType
	data      any
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ChainRuleData struct {
	ChainSelector uint64 `json:"chain_selector"`
}

type LaneRuleData struct {
	SelectorA uint64 `json:"selector_a"`
	SelectorB uint64 `json:"selector_b"`
}

type TokenRuleData struct {
	ChainSelector uint64 `json:"chain_selector"`
	TokenAddress  string `json:"token_address"`
}

type MessageReport interface {
	GetSourceChainSelector() uint64
	GetDestinationSelector() uint64
	GetTokenTransfer() *protocol.TokenTransfer
}

type messageReport struct {
	message protocol.Message
}

func NewMessageReport(message protocol.Message) MessageReport {
	return messageReport{message: message}
}

func (r messageReport) GetSourceChainSelector() uint64 {
	return uint64(r.message.SourceChainSelector)
}

func (r messageReport) GetDestinationSelector() uint64 {
	return uint64(r.message.DestChainSelector)
}

func (r messageReport) GetTokenTransfer() *protocol.TokenTransfer {
	return r.message.TokenTransfer
}

type Checker interface {
	IsDisabled(report MessageReport) bool
}

type NoopChecker struct{}

func (NoopChecker) IsDisabled(_ MessageReport) bool { return false }

func NewRuleID() string {
	return uuid.NewString()
}

func ValidateRuleID(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("rule id cannot be empty")
	}
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("rule id must be a valid UUID: %w", err)
	}
	return nil
}

func ParseRuleType(s string) (RuleType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case strings.ToLower(string(RuleTypeChain)):
		return RuleTypeChain, nil
	case strings.ToLower(string(RuleTypeLane)):
		return RuleTypeLane, nil
	case strings.ToLower(string(RuleTypeToken)):
		return RuleTypeToken, nil
	default:
		return "", fmt.Errorf("unknown rule type %q", s)
	}
}

func NormalizeTokenAddress(addr string) (string, error) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return "", errors.New("token address cannot be empty")
	}
	if !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}
	decoded, err := protocol.NewByteSliceFromHex(addr)
	if err != nil {
		return "", fmt.Errorf("invalid token address: %w", err)
	}
	if len(decoded) == 0 {
		return "", errors.New("token address cannot be empty")
	}
	return decoded.String(), nil
}

func (r Rule) ChainData() (ChainRuleData, error) {
	if r.Type != RuleTypeChain {
		return ChainRuleData{}, fmt.Errorf("rule type is %s, not Chain", r.Type)
	}

	data, ok := r.data.(ChainRuleData)
	if !ok {
		return ChainRuleData{}, fmt.Errorf("rule data is not a ChainRuleData")
	}
	return data, nil
}

func (r Rule) LaneData() (LaneRuleData, error) {
	if r.Type != RuleTypeLane {
		return LaneRuleData{}, fmt.Errorf("rule type is %s, not Lane", r.Type)
	}
	data, ok := r.data.(LaneRuleData)
	if !ok {
		return LaneRuleData{}, fmt.Errorf("rule data is not a LaneRuleData")
	}
	return data, nil
}

func (r Rule) TokenData() (TokenRuleData, error) {
	if r.Type != RuleTypeToken {
		return TokenRuleData{}, fmt.Errorf("rule type is %s, not Token", r.Type)
	}
	data, ok := r.data.(TokenRuleData)
	if !ok {
		return TokenRuleData{}, fmt.Errorf("rule data is not a TokenRuleData")
	}
	return data, nil
}
