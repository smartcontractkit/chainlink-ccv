// Package migration carries out the CL-mode to standalone cutover for a devenv node operator. It
// exists so the migration a real operator performs is exercised end to end rather than described
// in a document: the same key export — literally, via the shared migration package behind
// `ccv migrate export` — the same import path, the same JD identity handover. This package
// orchestrates the environment around that logic: containers, JD records, and job specs.
package migration

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"

	sharedmigration "github.com/smartcontractkit/chainlink-ccv/migration"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// ExportedNOPKeys is what one Chainlink node hands over: the two key files whose identities have
// to survive the move to standalone, and the addresses they carry.
//
// The CSA key is deliberately absent. It authenticates the node to JD and has no on-chain
// meaning, so rather than copying a private key out of the node, the cutover repoints the
// existing JD node record at the standalone verifier's own CSA key. That keeps the node
// operator's JD record, and its job history, without the key ever leaving the node it was
// generated on.
type ExportedNOPKeys struct {
	// NOPAlias is the node operator this material belongs to.
	NOPAlias string
	// OCR2BundlePath is the exported OCR2 EVM key bundle. Its onchain signing key is the identity
	// registered in the CommitteeVerifier signer set.
	OCR2BundlePath string
	// ETHKeyPath is the exported EVM account key: the funded transmitter the executor submits
	// from.
	ETHKeyPath string
	// PasswordPath is the file holding the password both exports were taken under.
	PasswordPath string
	// SigningAddress is the onchain signing address the OCR2 bundle carries, EIP-55 checksummed.
	SigningAddress string
	// TransmitterAddress is the EVM account address, EIP-55 checksummed.
	TransmitterAddress string
}

// ExportNOPKeys pulls the OCR2 EVM key bundle and EVM account key out of a running Chainlink
// node and writes them to outDir, along with the password file both are encrypted under.
//
// The work is done by the shared migration package — the same implementation `ccv migrate
// export` runs for a real operator — so the e2e test exercises the production path: the bundle
// and account are resolved from the node's own listings (the source its JD chain config was
// built from), both exports are decoded before this returns, and the transmitter is
// cross-checked against the account the node registered. A node in a shape the migration cannot
// adopt — several verifier jobs, several EVM bundles, several accounts on the chain — fails
// here, while it is still running, rather than midway through the cutover.
func ExportNOPKeys(
	ctx context.Context,
	clClient *clclient.ChainlinkClient,
	nopAlias, chainID, outDir string,
) (ExportedNOPKeys, error) {
	if clClient == nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: no Chainlink client", nopAlias)
	}

	result, err := sharedmigration.ExportNodeKeys(ctx, logger.Nop(), sharedmigration.ExportConfig{
		NodeURL:     clClient.URL(),
		APIEmail:    clClient.Config.Email,
		APIPassword: clClient.Config.Password,
		ChainID:     chainID,
		OutDir:      outDir,
	})
	if err != nil {
		return ExportedNOPKeys{}, fmt.Errorf("NOP %s: %w", nopAlias, err)
	}

	return ExportedNOPKeys{
		NOPAlias:           nopAlias,
		OCR2BundlePath:     result.OCR2Path,
		ETHKeyPath:         result.ETHPath,
		PasswordPath:       result.PasswordPath,
		SigningAddress:     result.SigningAddress,
		TransmitterAddress: result.TransmitterAddress,
	}, nil
}
