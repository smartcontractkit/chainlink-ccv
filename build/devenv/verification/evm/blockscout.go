package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog"

	"github.com/smartcontractkit/chainlink-ccv/devenv/verification"

	chainsel "github.com/smartcontractkit/chain-selectors"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

type blockscoutVerifyRequest struct {
	AddressHash      string `json:"addressHash"`
	CompilerVersion  string `json:"compilerVersion"`
	ContractSource   string `json:"contractSourceCode"`
	Name             string `json:"name"`
	OptimizationUsed bool   `json:"optimization"`
}

// BlockscoutContractVerifier verifies a contract on Blockscout.
type BlockscoutContractVerifier struct {
	chain                     chainsel.Chain
	apiURL                    string
	address                   string
	contractType              cldf.ContractType
	version                   *semver.Version
	input                     solidityContractMetadata
	verificationCheckInterval time.Duration
	lggr                      zerolog.Logger
}

func NewBlockscoutContractVerifier(
	apiURL string,
	address string,
	contractType cldf.ContractType,
	version *semver.Version,
	verificationCheckInterval time.Duration,
	lggr zerolog.Logger,
) (verification.Verifiable, error) {
	input, err := loadSolidityContractMetadata(contractType, version)
	if err != nil {
		return nil, fmt.Errorf("failed to load contract metadata: %w", err)
	}

	return &BlockscoutContractVerifier{
		apiURL:                    apiURL,
		address:                   address,
		contractType:              contractType,
		version:                   version,
		input:                     input,
		verificationCheckInterval: verificationCheckInterval,
		lggr:                      lggr,
	}, nil
}

func (v *BlockscoutContractVerifier) String() string {
	return fmt.Sprintf("%s %s (%s on %s)", v.contractType, v.version, v.address, v.chain.Name)
}

func (v *BlockscoutContractVerifier) IsVerified(ctx context.Context) (bool, error) {
	u, err := url.Parse(v.apiURL)
	if err != nil {
		return false, fmt.Errorf("failed to parse API URL: %w", err)
	}
	q := u.Query()
	q.Set("module", "contract")
	q.Set("action", "getabi")
	q.Set("address", v.address)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Result  string `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Status == "1" && result.Result != "" {
		v.lggr.Info().
			Str("address", v.address).
			Msg("Contract is verified")
		return true, nil
	}

	return false, nil
}

func (v *BlockscoutContractVerifier) Verify(ctx context.Context) error {
	verified, err := v.IsVerified(ctx)
	if err != nil {
		return err
	}
	if verified {
		v.lggr.Info().Str("address", v.address).Msg("Contract is already verified")
		return nil
	}
	sourceCode, err := v.input.SourceCode()
	if err != nil {
		return fmt.Errorf("failed to get source code: %w", err)
	}

	verifyRequest := blockscoutVerifyRequest{
		AddressHash:      v.address,
		CompilerVersion:  v.input.Version,
		ContractSource:   sourceCode,
		Name:             v.contractType.String(),
		OptimizationUsed: true,
	}

	u, err := url.Parse(v.apiURL)
	if err != nil {
		return fmt.Errorf("invalid API URL: %w", err)
	}
	u.Path = "/api"
	q := u.Query()
	q.Set("module", "contract")
	q.Set("action", "verify")
	u.RawQuery = q.Encode()

	verified, err = sendBlockscoutPOSTRequest(ctx, u.String(), verifyRequest)
	if err != nil {
		return err
	}

	if verified {
		v.lggr.Info().Str("address", v.address).Msg("Contract verification submitted successfully")
	} else {
		return errors.New("verification failed with unexpected status code")
	}

	return nil // No polling because Blockscout may not return GUIDs reliably
}

func sendBlockscoutPOSTRequest(ctx context.Context, url string, data interface{}) (bool, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("http error - status=%d body=%s", resp.StatusCode, string(body))
	}

	return true, nil
}
