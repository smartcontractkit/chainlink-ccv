// Package migration carries out the CL-mode to standalone cutover for a devenv node operator. It
// exists so the migration a real operator performs is exercised end to end rather than described in
// a document: the same key export, the same import path, the same JD identity handover.
package migration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccv/bootstrap/keys"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
)

// ExportPassword is the password devenv exports every Chainlink node key under. A devenv value is
// deliberately fixed and obvious; an operator supplies their own and keeps the file out of source
// control.
const ExportPassword = "devenv-key-export-password"

// ExportedNOPKeys is what one Chainlink node hands over: the two key files whose identities have to
// survive the move to standalone, and the addresses they carry.
//
// The CSA key is deliberately absent. It authenticates the node to JD and has no on-chain meaning,
// so rather than copying a private key out of the node, the cutover repoints the existing JD node
// record at the standalone verifier's own CSA key. That keeps the node operator's JD record, and
// its job history, without the key ever leaving the node it was generated on.
type ExportedNOPKeys struct {
	// NOPAlias is the node operator this material belongs to.
	NOPAlias string
	// OCR2BundlePath is the exported OCR2 EVM key bundle. Its onchain signing key is the identity
	// registered in the CommitteeVerifier signer set.
	OCR2BundlePath string
	// ETHKeyPath is the exported EVM account key: the funded transmitter the executor submits from.
	ETHKeyPath string
	// PasswordPath is the file holding the password both exports were taken under.
	PasswordPath string
	// SigningAddress is the onchain signing address the OCR2 bundle carries, EIP-55 checksummed.
	SigningAddress string
	// TransmitterAddress is the EVM account address, EIP-55 checksummed.
	TransmitterAddress string
}

// ExportNOPKeys pulls the OCR2 EVM key bundle and EVM account key out of a running Chainlink node
// and writes them to outDir, along with the password file both are encrypted under.
//
// The two keys are chosen the same way the node's JD chain config was built (jobs/jd.go): the OCR2
// bundle registered for EVM and the account address registered for chainID. Taking them from the
// same source is what makes the migration a no-op on chain — any other bundle or account would
// import an identity no contract has heard of.
//
// Each export is decoded before this returns, so a file that cannot be read back fails here rather
// than at container startup, when the CL node it came from may already be stopped.
func ExportNOPKeys(
	ctx context.Context,
	clClient *clclient.ChainlinkClient,
	nopAlias, chainID, outDir string,
) (ExportedNOPKeys, error) {
	if clClient == nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: no Chainlink client", nopAlias)
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: failed to create export directory: %w", nopAlias, err)
	}

	gqlClient, err := jobs.NewSDKClient(ctx, clClient)
	if err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: failed to create node API client: %w", nopAlias, err)
	}
	bundleID, err := gqlClient.FetchOCR2KeyBundleID(ctx, "EVM")
	if err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: failed to read the EVM OCR2 key bundle ID: %w", nopAlias, err)
	}
	accountAddr, err := gqlClient.FetchAccountAddress(ctx, chainID)
	if err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: failed to read the EVM account address: %w", nopAlias, err)
	}
	if accountAddr == nil || *accountAddr == "" {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: node reports no EVM account for chain %s", nopAlias, chainID)
	}

	passwordPath := filepath.Join(outDir, "export-password.txt")
	if err := os.WriteFile(passwordPath, []byte(ExportPassword), 0o600); err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: failed to write password file: %w", nopAlias, err)
	}

	ocr2Path := filepath.Join(outDir, "ocr2.json")
	if err := exportKey(clClient, "/v2/keys/ocr2/export/{id}", "id", bundleID, ocr2Path); err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: failed to export OCR2 key bundle %s: %w", nopAlias, bundleID, err)
	}
	ethPath := filepath.Join(outDir, "eth.json")
	if err := exportKey(clClient, "/v2/keys/eth/export/{address}", "address", *accountAddr, ethPath); err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: failed to export EVM account %s: %w", nopAlias, *accountAddr, err)
	}

	signingAddress, err := keys.InspectImport(keys.Import{
		Format:       keys.ImportFormatOCR2,
		Path:         ocr2Path,
		PasswordPath: passwordPath,
	})
	if err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: exported OCR2 bundle is unusable: %w", nopAlias, err)
	}
	transmitterAddress, err := keys.InspectImport(keys.Import{
		Format:       keys.ImportFormatETH,
		Path:         ethPath,
		PasswordPath: passwordPath,
	})
	if err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: exported EVM account key is unusable: %w", nopAlias, err)
	}
	// The node reported this account when its JD chain config was created, so a mismatch means the
	// export endpoint returned a different key than the one that address names.
	if !strings.EqualFold(transmitterAddress, strings.TrimPrefix(*accountAddr, "0x")) {
		return ExportedNOPKeys{}, fmt.Errorf(
			"NOP %s: exported EVM key holds 0x%s but the node registered %s", nopAlias, transmitterAddress, *accountAddr)
	}

	return ExportedNOPKeys{
		NOPAlias:           nopAlias,
		OCR2BundlePath:     ocr2Path,
		ETHKeyPath:         ethPath,
		PasswordPath:       passwordPath,
		SigningAddress:     toChecksumAddress(signingAddress),
		TransmitterAddress: toChecksumAddress(transmitterAddress),
	}, nil
}

// exportKey calls one of the node's key export endpoints and writes the response body verbatim.
// The raw body is kept rather than a decoded-and-re-encoded struct: it is byte-for-byte the file
// `chainlink keys ... export` writes, which is the input an operator will actually have.
func exportKey(clClient *clclient.ChainlinkClient, path, param, value, outPath string) error {
	resp, err := clClient.APIClient.R().
		SetPathParam(param, value).
		SetQueryParam("newpassword", ExportPassword).
		Post(path)
	if err != nil {
		return fmt.Errorf("export request failed: %w", err)
	}
	if resp.IsError() {
		return fmt.Errorf("export request returned %d: %s", resp.StatusCode(), resp.String())
	}
	body := resp.Body()
	if len(body) == 0 {
		return fmt.Errorf("export request returned an empty body")
	}
	if err := os.WriteFile(outPath, body, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", outPath, err)
	}
	return nil
}

func toChecksumAddress(hexAddress string) string {
	return common.HexToAddress(hexAddress).Hex()
}
