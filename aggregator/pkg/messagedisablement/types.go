package messagedisablement

import (
	"context"
	"encoding/json"
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
	Data      json.RawMessage
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

type Store interface {
	// Create persists a new message disablement rule.
	Create(ctx context.Context, ruleType RuleType, data json.RawMessage) (Rule, error)
	// List returns message disablement rules, optionally filtered by type.
	List(ctx context.Context, ruleType *RuleType) ([]Rule, error)
	// Get returns a message disablement rule by id, or nil when it does not exist.
	Get(ctx context.Context, id string) (*Rule, error)
	// Delete removes a message disablement rule by id.
	Delete(ctx context.Context, id string) error
}

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

func NewChainRuleData(selector uint64) (json.RawMessage, error) {
	return normalizeChainRuleData(ChainRuleData{ChainSelector: selector})
}

func NewLaneRuleData(selectorA, selectorB uint64) (json.RawMessage, error) {
	return normalizeLaneRuleData(LaneRuleData{SelectorA: selectorA, SelectorB: selectorB})
}

func NewTokenRuleData(selector uint64, tokenAddress string) (json.RawMessage, error) {
	token, err := NormalizeTokenAddress(tokenAddress)
	if err != nil {
		return nil, err
	}
	return normalizeTokenRuleData(TokenRuleData{ChainSelector: selector, TokenAddress: token})
}

func NormalizeRuleData(ruleType RuleType, data json.RawMessage) (json.RawMessage, error) {
	switch ruleType {
	case RuleTypeChain:
		var ruleData ChainRuleData
		if err := json.Unmarshal(data, &ruleData); err != nil {
			return nil, fmt.Errorf("invalid Chain rule data: %w", err)
		}
		return normalizeChainRuleData(ruleData)
	case RuleTypeLane:
		var ruleData LaneRuleData
		if err := json.Unmarshal(data, &ruleData); err != nil {
			return nil, fmt.Errorf("invalid Lane rule data: %w", err)
		}
		return normalizeLaneRuleData(ruleData)
	case RuleTypeToken:
		var ruleData TokenRuleData
		if err := json.Unmarshal(data, &ruleData); err != nil {
			return nil, fmt.Errorf("invalid Token rule data: %w", err)
		}
		token, err := NormalizeTokenAddress(ruleData.TokenAddress)
		if err != nil {
			return nil, err
		}
		ruleData.TokenAddress = token
		return normalizeTokenRuleData(ruleData)
	default:
		return nil, fmt.Errorf("unknown rule type %q", ruleType)
	}
}

func (r Rule) ChainData() (ChainRuleData, error) {
	if r.Type != RuleTypeChain {
		return ChainRuleData{}, fmt.Errorf("rule type is %s, not Chain", r.Type)
	}
	var data ChainRuleData
	if err := json.Unmarshal(r.Data, &data); err != nil {
		return ChainRuleData{}, err
	}
	normalized, err := normalizeChainRuleData(data)
	if err != nil {
		return ChainRuleData{}, err
	}
	if err := json.Unmarshal(normalized, &data); err != nil {
		return ChainRuleData{}, err
	}
	return data, nil
}

func (r Rule) LaneData() (LaneRuleData, error) {
	if r.Type != RuleTypeLane {
		return LaneRuleData{}, fmt.Errorf("rule type is %s, not Lane", r.Type)
	}
	var data LaneRuleData
	if err := json.Unmarshal(r.Data, &data); err != nil {
		return LaneRuleData{}, err
	}
	normalized, err := normalizeLaneRuleData(data)
	if err != nil {
		return LaneRuleData{}, err
	}
	if err := json.Unmarshal(normalized, &data); err != nil {
		return LaneRuleData{}, err
	}
	return data, nil
}

func (r Rule) TokenData() (TokenRuleData, error) {
	if r.Type != RuleTypeToken {
		return TokenRuleData{}, fmt.Errorf("rule type is %s, not Token", r.Type)
	}
	var data TokenRuleData
	if err := json.Unmarshal(r.Data, &data); err != nil {
		return TokenRuleData{}, err
	}
	normalized, err := normalizeTokenRuleData(data)
	if err != nil {
		return TokenRuleData{}, err
	}
	if err := json.Unmarshal(normalized, &data); err != nil {
		return TokenRuleData{}, err
	}
	return data, nil
}

func normalizeChainRuleData(data ChainRuleData) (json.RawMessage, error) {
	if data.ChainSelector == 0 {
		return nil, errors.New("chain selector cannot be zero")
	}
	return json.Marshal(data)
}

func normalizeLaneRuleData(data LaneRuleData) (json.RawMessage, error) {
	if data.SelectorA == 0 || data.SelectorB == 0 {
		return nil, errors.New("lane selectors cannot be zero")
	}
	if data.SelectorA == data.SelectorB {
		return nil, errors.New("lane selectors must be different")
	}
	if data.SelectorB < data.SelectorA {
		data.SelectorA, data.SelectorB = data.SelectorB, data.SelectorA
	}
	return json.Marshal(data)
}

func normalizeTokenRuleData(data TokenRuleData) (json.RawMessage, error) {
	if data.ChainSelector == 0 {
		return nil, errors.New("chain selector cannot be zero")
	}
	token, err := NormalizeTokenAddress(data.TokenAddress)
	if err != nil {
		return nil, err
	}
	data.TokenAddress = token
	return json.Marshal(data)
}
