package migration

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/clclient"
	ctfblockchain "github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/chainreg"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/jobs"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/services/committeeverifier"
	executorsvc "github.com/smartcontractkit/chainlink-ccv/build/devenv/services/executor"
	ccvdeployment "github.com/smartcontractkit/chainlink-ccv/deployment"
	ccvshared "github.com/smartcontractkit/chainlink-ccv/deployment/shared"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
	hmacutil "github.com/smartcontractkit/chainlink-ccv/protocol/common/hmac"
)

// nodeConnectTimeout bounds the wait for a standalone process to authenticate with JD. It is
// generous because the verifier has to come up, import a key, and dial JD before it counts.
const nodeConnectTimeout = 90 * time.Second

// NOP is one node operator moving from CL mode to standalone.
type NOP struct {
	// Alias is the node operator's alias, which is also the name of its JD node record.
	Alias string
	// CLClient talks to the Chainlink node that currently runs this operator's CCV jobs.
	CLClient *clclient.ChainlinkClient
	// CLContainerNames are the containers to stop once the keys are out.
	CLContainerNames []string
}

// Input is the running environment, unpacked into what the cutover needs. It takes the pieces
// rather than the whole devenv config so this package stays independent of the environment package
// that assembles it.
type Input struct {
	// NOPs are the node operators to migrate. Operators absent from this list keep running in CL
	// mode, so a deployment can be moved a few operators at a time.
	NOPs []NOP
	// Verifiers and Executors are the service inputs from the running environment. Entries whose
	// NOPAlias names a migrating operator are flipped to standalone and launched; the rest are left
	// alone.
	Verifiers []*committeeverifier.Input
	Executors []*executorsvc.Input
	// Aggregators must already be running, so each migrating verifier can be given the HMAC
	// credentials its committee's aggregators accept. Aggregators loaded from a devenv output file
	// are fine: the credential map itself is not serialized, and is rebuilt here from the API client
	// config that is.
	Aggregators []*services.AggregatorInput
	// BlockchainOutputs are the chains the launched services connect to.
	BlockchainOutputs []*ctfblockchain.Output
	// JDInfra carries the JD output and a live offchain client.
	JDInfra *jobs.JDInfrastructure
	// Topology is mutated in place: each migrated operator's mode becomes standalone, so the job
	// spec changesets emit standalone-shaped specs on their next run.
	Topology *ccvdeployment.EnvironmentTopology
	// WorkDir is where exported key material is written, one subdirectory per operator.
	WorkDir string
}

// NOPResult records what one operator's cutover produced, for assertions and for the operator's own
// records.
type NOPResult struct {
	Alias string
	// VerifierJDNodeID is the record the Chainlink node used, now owned by the standalone verifier.
	VerifierJDNodeID string
	// ExecutorJDNodeIDs are the records registered for this operator's standalone executors.
	ExecutorJDNodeIDs []string
	// SigningAddress is the verifier signing identity carried across, EIP-55 checksummed. It must
	// equal what it was before the cutover; that equality is the whole point. The executor's
	// transmitter is deliberately not carried across (see Run), so there is no analogous field for it.
	SigningAddress string

	// adopted guards against handing one JD record to two verifier processes.
	adopted bool
}

// Result is the outcome of the cutover, keyed by node operator alias.
type Result struct {
	NOPs map[string]*NOPResult
}

// Run performs the cutover. The ordering is not incidental:
//
//  1. Read each Chainlink node's CSA key and find its JD record, while the node is still up.
//  2. Export the OCR2 onchain signing key from each node.
//  3. Stop the Chainlink nodes. Their JD records are about to change hands, and a connected node
//     would contend with the process taking over.
//  4. Launch the standalone verifiers, which import the signing keys.
//  5. Repoint each JD record at its verifier's own CSA key, and wait for the verifier to connect.
//  6. Launch the standalone executors, fund their transmitters, and register them as new JD nodes.
//  7. Flip each operator's mode in the topology.
//
// The verifier's signing key is carried across; the executor's transmitter is not. The standalone
// executor generates its own key rather than importing the node's per-chain account, so unlike the
// signing address it is a fresh account that has to be funded here before it can submit. This is the
// single-key executor a live deployment runs: one funded account per operator instead of the
// node's per-chain transmitters. What still moves per operator is the verifier identity plus a
// working standalone executor; what does not move is the operator's gas.
//
// Proposing the standalone job specs is left to the caller, which re-runs ApplyVerifierConfig and
// ApplyExecutorConfig against the mutated topology. Keeping that out of here means the cutover does
// not need a CLDF environment and stays testable against the services alone.
func Run(ctx context.Context, in Input) (Result, error) {
	result := Result{NOPs: make(map[string]*NOPResult, len(in.NOPs))}
	if len(in.NOPs) == 0 {
		return result, nil
	}
	if in.JDInfra == nil || in.JDInfra.OffchainClient == nil {
		return result, fmt.Errorf("cutover requires a JD client")
	}
	if in.Topology == nil || in.Topology.NOPTopology == nil {
		return result, fmt.Errorf("cutover requires an environment topology")
	}

	migrating := make(map[string]struct{}, len(in.NOPs))
	for _, nop := range in.NOPs {
		migrating[nop.Alias] = struct{}{}
	}

	// Step 1 and 2, before anything is stopped: the node's CSA key, its JD record, and its signing
	// key are all readable only while it is running.
	exported := make(map[string]ExportedNOPKeys, len(in.NOPs))
	var clContainers []string
	for _, nop := range in.NOPs {
		if _, ok := in.Topology.NOPTopology.GetNOPIndex(nop.Alias); !ok {
			return result, fmt.Errorf("NOP %s is not in the environment topology", nop.Alias)
		}
		csaKey, err := jobs.CLCSAKeyProvider{Client: nop.CLClient}.CSAKey(ctx)
		if err != nil {
			return result, fmt.Errorf("NOP %s: failed to read the Chainlink node's CSA key: %w", nop.Alias, err)
		}
		node, err := FindNodeByCSAKey(ctx, in.JDInfra.OffchainClient, csaKey)
		if err != nil {
			return result, fmt.Errorf("NOP %s: %w", nop.Alias, err)
		}

		keyMaterial, err := ExportNOPKeys(ctx, nop.CLClient, nop.Alias,
			filepath.Join(in.WorkDir, nop.Alias))
		if err != nil {
			return result, err
		}
		exported[nop.Alias] = keyMaterial
		clContainers = append(clContainers, nop.CLContainerNames...)
		result.NOPs[nop.Alias] = &NOPResult{
			Alias:            nop.Alias,
			VerifierJDNodeID: node.GetId(),
			SigningAddress:   keyMaterial.SigningAddress,
		}
	}

	// Step 3.
	if err := StopCLNodes(ctx, clContainers); err != nil {
		return result, err
	}

	// Step 4.
	if err := prepareVerifiers(in.Verifiers, migrating, exported); err != nil {
		return result, err
	}
	hydrateAggregatorCredentials(in.Aggregators)
	if err := committeeverifier.LaunchStandaloneVerifiers(
		in.Verifiers,
		in.Aggregators,
		committeeverifier.CommitteeAggregatorNames(in.Topology),
		in.BlockchainOutputs,
		in.JDInfra,
		chainreg.GetRegistry().GetVerifierModifiers(),
	); err != nil {
		return result, fmt.Errorf("failed to launch standalone verifiers: %w", err)
	}

	// Step 5. RegisterStandaloneVerifiersWithJD is deliberately not used here: it registers a new
	// node under the operator's alias, which is the duplicate entry this migration exists to avoid.
	// The existing record is repointed instead.
	if err := adoptVerifierIdentities(ctx, in, migrating, result); err != nil {
		return result, err
	}

	// Step 6.
	prepareExecutors(in.Executors, migrating)
	if err := launchExecutors(ctx, in, migrating, result); err != nil {
		return result, err
	}

	// Step 7. Done last: until every process is up and connected, the topology still describes what
	// is actually running.
	for alias := range migrating {
		idx, ok := in.Topology.NOPTopology.GetNOPIndex(alias)
		if !ok {
			return result, fmt.Errorf("NOP %s vanished from the topology during cutover", alias)
		}
		in.Topology.NOPTopology.NOPs[idx].Mode = ccvshared.NOPModeStandalone
	}
	return result, nil
}

// hydrateAggregatorCredentials rebuilds the ClientCredentials map of every running aggregator that
// arrived without one.
//
// AggregatorOutput.ClientCredentials is toml:"-", so an environment loaded from a devenv output
// file carries every other part of the aggregator's Out but not that map — and a verifier launched
// without it cannot authenticate. The keys themselves do survive, under
// api_clients.api_key_pairs, so the map is rebuilt from those.
//
// They are read, never generated. The aggregator is already running with the credentials it was
// started with, so minting a fresh pair here would hand the verifier something the aggregator has
// never seen: a runtime authentication failure rather than an error anyone can act on. An
// aggregator whose keys cannot be recovered is left alone, so the verifier that actually needs them
// reports it by name in AggregatorCredentialsForVerifier.
func hydrateAggregatorCredentials(aggregators []*services.AggregatorInput) {
	for _, agg := range aggregators {
		if agg == nil || agg.Out == nil || len(agg.Out.ClientCredentials) > 0 {
			continue
		}
		creds := make(map[string]hmacutil.Credentials, len(agg.APIClients))
		for _, client := range agg.APIClients {
			if client == nil {
				continue
			}
			for _, pair := range client.APIKeyPairs {
				if pair == nil || pair.APIKey == "" || pair.Secret == "" {
					continue
				}
				// The first usable pair, matching how EnsureClientCredentials keys the map: a client
				// with several pairs is rotating them, and either is accepted.
				creds[client.ClientID] = hmacutil.Credentials{APIKey: pair.APIKey, Secret: pair.Secret}
				break
			}
		}
		if len(creds) > 0 {
			agg.Out.ClientCredentials = creds
		}
	}
}

// prepareVerifiers flips each migrating operator's verifiers to standalone and points them at the
// exported signing key.
func prepareVerifiers(
	verifiers []*committeeverifier.Input,
	migrating map[string]struct{},
	exported map[string]ExportedNOPKeys,
) error {
	for _, ver := range verifiers {
		if ver == nil {
			continue
		}
		if _, ok := migrating[ver.NOPAlias]; !ok {
			continue
		}
		keyMaterial := exported[ver.NOPAlias]
		if ver.Bootstrap == nil {
			ver.Bootstrap = &services.BootstrapInput{}
		}
		keyImport, files, err := services.BuildKeyImport(
			keyMaterial.OCR2BundlePath, keyMaterial.PasswordPath, keyMaterial.SigningAddress)
		if err != nil {
			return fmt.Errorf("verifier %s: %w", ver.ContainerName, err)
		}
		ver.Bootstrap.KeyImport = keyImport
		ver.Bootstrap.KeyImportFiles = files
		ver.Mode = services.Standalone
	}
	return nil
}

// adoptVerifierIdentities hands each operator's JD record to its standalone verifier and waits for
// the verifier to claim it.
func adoptVerifierIdentities(
	ctx context.Context,
	in Input,
	migrating map[string]struct{},
	result Result,
) error {
	for _, ver := range in.Verifiers {
		if ver == nil {
			continue
		}
		if _, ok := migrating[ver.NOPAlias]; !ok {
			continue
		}
		nopResult, ok := result.NOPs[ver.NOPAlias]
		if !ok {
			return fmt.Errorf("verifier %s: no cutover record for NOP %s", ver.ContainerName, ver.NOPAlias)
		}
		if ver.Out == nil || ver.Out.BootstrapKeys.CSAPublicKey == "" {
			return fmt.Errorf("verifier %s started but exposed no CSA public key", ver.ContainerName)
		}
		if ver.Out.JDNodeID != "" && ver.Out.JDNodeID != nopResult.VerifierJDNodeID {
			return fmt.Errorf("verifier %s already owns JD node %s", ver.ContainerName, ver.Out.JDNodeID)
		}
		// A standalone process runs one job, because lifecycle.Manager holds a single current job. An
		// operator still on per-aggregator verifier jobs therefore needs one process per job, and
		// those are separate CSA keys that one JD record cannot cover. Consolidating the committee's
		// verifier jobs first (NewConsolidatedVerifierJobID) brings the operator to a single verifier
		// job, which is the shape this cutover adopts a record for.
		if nopResult.adopted {
			return fmt.Errorf(
				"NOP %s has more than one standalone verifier (%s and others), which happens when its "+
					"committee still proposes a verifier job per aggregator; consolidate the committee's "+
					"verifier jobs before migrating so the operator runs a single verifier process",
				ver.NOPAlias, ver.ContainerName)
		}

		if err := AdoptJDIdentity(ctx, in.JDInfra.OffchainClient,
			nopResult.VerifierJDNodeID, ver.NOPAlias, ver.Out.BootstrapKeys.CSAPublicKey); err != nil {
			return err
		}
		if err := jobs.WaitForNodeConnection(ctx, in.JDInfra.OffchainClient,
			nopResult.VerifierJDNodeID, nodeConnectTimeout); err != nil {
			return fmt.Errorf("verifier %s: %w", ver.ContainerName, err)
		}
		ver.Out.JDNodeID = nopResult.VerifierJDNodeID
		in.JDInfra.RegisterNodeAlias(ver.NOPAlias, nopResult.VerifierJDNodeID)
		nopResult.adopted = true
	}
	return nil
}

// prepareExecutors flips each migrating operator's executors to standalone. Unlike the verifier,
// nothing is imported: the standalone executor generates its own transmitter key, the single funded
// account that replaces the node's per-chain transmitters. launchExecutors funds it once the
// container is up and has exposed the key.
func prepareExecutors(executors []*executorsvc.Input, migrating map[string]struct{}) {
	for _, exec := range executors {
		if exec == nil {
			continue
		}
		if _, ok := migrating[exec.NOPAlias]; !ok {
			continue
		}
		exec.Mode = services.Standalone
	}
}

// launchExecutors starts each migrating operator's standalone executors, funds the transmitter each
// one generated, and registers them as new JD nodes under their container names, which is how a
// standalone environment names them.
func launchExecutors(
	ctx context.Context,
	in Input,
	migrating map[string]struct{},
	result Result,
) error {
	for _, exec := range in.Executors {
		if exec == nil {
			continue
		}
		if _, ok := migrating[exec.NOPAlias]; !ok {
			continue
		}
		executorsvc.ApplyDefaults(exec)

		var transmitterKeyName string
		if familyReg, err := chainreg.GetRegistry().Get(exec.ChainFamily); err == nil && familyReg.ExecutorInfo != nil {
			transmitterKeyName = familyReg.ExecutorInfo.ExecutorTransmitterKeyName()
		}
		out, err := executorsvc.New(exec, in.BlockchainOutputs, in.JDInfra,
			chainreg.GetRegistry().GetExecutorModifiers(), transmitterKeyName)
		if err != nil {
			return fmt.Errorf("failed to launch standalone executor %s: %w", exec.ContainerName, err)
		}
		exec.Out = out

		if out.BootstrapKeys.CSAPublicKey == "" {
			return fmt.Errorf("executor %s started but exposed no CSA public key", exec.ContainerName)
		}

		// The executor generated its own transmitter key, which holds no gas until this funds it. Do
		// it before the job is proposed, so the executor can submit the moment it starts.
		if err := fundExecutorTransmitter(ctx, exec, in.BlockchainOutputs); err != nil {
			return fmt.Errorf("executor %s: %w", exec.ContainerName, err)
		}

		reg := &jobs.BootstrapJDRegistration{
			Name:         exec.ContainerName,
			CSAPublicKey: out.BootstrapKeys.CSAPublicKey,
		}
		if err := jobs.RegisterBootstrapWithJD(ctx, in.JDInfra.OffchainClient, reg); err != nil {
			return fmt.Errorf("failed to register standalone executor %s with JD: %w", exec.ContainerName, err)
		}
		if err := jobs.WaitForNodeConnection(ctx, in.JDInfra.OffchainClient, reg.NodeID, nodeConnectTimeout); err != nil {
			return fmt.Errorf("executor %s: %w", exec.ContainerName, err)
		}
		out.JDNodeID = reg.NodeID

		if nopResult, ok := result.NOPs[exec.NOPAlias]; ok {
			nopResult.ExecutorJDNodeIDs = append(nopResult.ExecutorJDNodeIDs, reg.NodeID)
		}
	}
	return nil
}

// fundExecutorTransmitter funds the address the launched executor transmits from, on every chain of
// its family, so its fresh key can pay for execution. The funder is the chain's well-known dev
// account — the same one the environment funds every node and transmitter from — reached through the
// family's CCIP configuration. This mirrors the environment's own executor funding; it lives here
// because the cutover launches these executors after the environment is already up.
func fundExecutorTransmitter(ctx context.Context, exec *executorsvc.Input, blockchainOutputs []*ctfblockchain.Output) error {
	reg, err := chainreg.GetRegistry().Get(exec.ChainFamily)
	if err != nil || reg.ExecutorInfo == nil || reg.ImplFactory == nil || !reg.ImplFactory.SupportsFunding() {
		return nil
	}
	addrHex := reg.ExecutorInfo.ExecutorTransmitterAddress(exec.Out.BootstrapKeys)
	if addrHex == "" {
		return fmt.Errorf("executor exposed no transmitter address to fund")
	}
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return fmt.Errorf("invalid transmitter address %q: %w", addrHex, err)
	}
	addresses := []protocol.UnknownAddress{protocol.UnknownAddress(addrBytes)}

	for _, out := range blockchainOutputs {
		if out == nil || out.Family != exec.ChainFamily {
			continue
		}
		impl := reg.ImplFactory.NewEmpty()
		bc := &ctfblockchain.Input{ChainID: out.ChainID, Out: out}
		if err := impl.FundAddresses(ctx, bc, addresses, big.NewInt(5)); err != nil {
			return fmt.Errorf("funding transmitter on chain %s: %w", out.ChainID, err)
		}
	}
	return nil
}
