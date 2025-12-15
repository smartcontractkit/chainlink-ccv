package gencfg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"

	"github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/committee_verifier"
	executor_operations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/executor"
	offrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/offramp"
	onrampoperations "github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment/v1_7_0/operations/onramp"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/operations/rmn_remote"
	ccv "github.com/smartcontractkit/chainlink-ccv/devenv"
	"github.com/smartcontractkit/chainlink-ccv/devenv/services"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
)

func ocrThreshold(n int) uint8 {
	f := (n - 1) / 3
	return uint8(f + 1)
}

func GenerateConfigs(cldDomain string, verifierPubKeys []string, numExecutors int, createPR bool) (string, error) {
	// Validate environment
	ctx := context.Background()

	ccv.Plog.Info().
		Str("cldDomain", cldDomain).
		Strs("verifierPubKeys", verifierPubKeys).
		Int("numExecutors", numExecutors).
		Bool("createPR", createPR).
		Msg("Generating configs")

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return "", fmt.Errorf("GITHUB_TOKEN environment variable is not set. Run `export GITHUB_TOKEN=$(gh auth token)`")
	}
	// Create GH client
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")},
	)
	tc := oauth2.NewClient(ctx, ts)
	gh := github.NewClient(tc)

	// Fetch address refs file from github
	addressRefsGh, _, _, err := gh.Repositories.GetContents(ctx, "smartcontractkit", "chainlink-deployments", fmt.Sprintf("domains/ccv/%s/datastore/address_refs.json", cldDomain), &github.RepositoryContentGetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get address refs JSON from GitHub: %w", err)
	}
	f, _ := base64.StdEncoding.DecodeString(*addressRefsGh.Content)

	var addressRefs []datastore.AddressRef
	if err := json.Unmarshal(f, &addressRefs); err != nil {
		return "", fmt.Errorf("failed to decode address refs JSON: %w", err)
	}

	const (
		verifierIDPrefix                   = "default-verifier-"
		executorIDPrefix                   = "default-executor-"
		committeeName                      = "default"
		monitoringOtelExporterHTTPEndpoint = "prod.telemetry.chain.link:443"
		aggregatorAddress                  = "http://chainlink-ccv-aggregator:50051"
		indexerAddress                     = "http://chainlink-ccv-indexer:8100"
	)

	var (
		onRampAddresses                         = make(map[string]string)
		committeeVerifierAddresses              = make(map[string]string)
		committeeVerifierResolverProxyAddresses = make(map[uint64]string)
		defaultExecutorOnRampAddresses          = make(map[string]string)
		defaultExecutorOnRampAddressesUint64    = make(map[uint64]string)
		rmnRemoteAddresses                      = make(map[string]string)
		rmnRemoteAddressesUint64                = make(map[uint64]string)
		offRampAddresses                        = make(map[uint64]string)
		thresholdPerSource                      = make(map[uint64]uint8)
	)

	for _, ref := range addressRefs {
		chainSelectorStr := strconv.FormatUint(ref.ChainSelector, 10)
		switch ref.Type {
		case datastore.ContractType(onrampoperations.ContractType):
			onRampAddresses[chainSelectorStr] = ref.Address
		case datastore.ContractType(committee_verifier.ResolverProxyType):
			committeeVerifierAddresses[chainSelectorStr] = ref.Address
			committeeVerifierResolverProxyAddresses[ref.ChainSelector] = ref.Address
		case datastore.ContractType(executor_operations.ContractType):
			defaultExecutorOnRampAddresses[chainSelectorStr] = ref.Address
			defaultExecutorOnRampAddressesUint64[ref.ChainSelector] = ref.Address
		case datastore.ContractType(rmn_remote.ContractType):
			rmnRemoteAddresses[chainSelectorStr] = ref.Address
			rmnRemoteAddressesUint64[ref.ChainSelector] = ref.Address
		case datastore.ContractType(offrampoperations.ContractType):
			offRampAddresses[ref.ChainSelector] = ref.Address
		}
		thresholdPerSource[ref.ChainSelector] = ocrThreshold(len(verifierPubKeys))
	}

	tempDir, err := os.MkdirTemp("", "ccv-configs")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}
	ccv.Plog.Info().Str("temp-dir", tempDir).Msg("Created temporary directory for configs")

	// Verifier inputs
	verifierInputs := make([]*services.VerifierInput, 0, len(verifierPubKeys))
	for i, pubKey := range verifierPubKeys {
		verifierInputs = append(verifierInputs, &services.VerifierInput{
			ContainerName:                      fmt.Sprintf("%s%d", verifierIDPrefix, i),
			AggregatorAddress:                  aggregatorAddress,
			SigningKeyPublic:                   pubKey,
			CommitteeVerifierAddresses:         committeeVerifierAddresses,
			OnRampAddresses:                    onRampAddresses,
			DefaultExecutorOnRampAddresses:     defaultExecutorOnRampAddresses,
			RMNRemoteAddresses:                 rmnRemoteAddresses,
			CommitteeName:                      committeeName,
			MonitoringOtelExporterHTTPEndpoint: monitoringOtelExporterHTTPEndpoint,
		})
	}

	for _, verifierInput := range verifierInputs {
		verifierJobSpec, err := verifierInput.GenerateJobSpec()
		if err != nil {
			return "", fmt.Errorf("failed to generate verifier job spec: %w", err)
		}
		ccv.Plog.Info().Msg("Generated verifier job spec, writing to temporary directory as a separate file")
		filePath := filepath.Join(tempDir, fmt.Sprintf("verifier-%s-job-spec.toml", verifierInput.ContainerName))
		if err := os.WriteFile(filePath, []byte(verifierJobSpec), 0o644); err != nil {
			return "", fmt.Errorf("failed to write verifier job spec to file: %w", err)
		}
		ccv.Plog.Info().Str("file-path", filePath).Msg("Wrote verifier job spec to file")
	}

	// Executor inputs
	executorInputs := make([]services.ExecutorInput, 0, numExecutors)
	executorPool := make([]string, 0, numExecutors)
	for i := 0; i < numExecutors; i++ {
		executorPool = append(executorPool, fmt.Sprintf("%s%d", executorIDPrefix, i))
	}
	for i := 0; i < numExecutors; i++ {
		executorInputs = append(executorInputs, services.ExecutorInput{
			ExecutorID:                         fmt.Sprintf("%s%d", executorIDPrefix, i),
			ExecutorPool:                       executorPool,
			OfframpAddresses:                   offRampAddresses,
			IndexerAddress:                     indexerAddress,
			ExecutorAddresses:                  defaultExecutorOnRampAddressesUint64,
			RmnAddresses:                       rmnRemoteAddressesUint64,
			MonitoringOtelExporterHTTPEndpoint: monitoringOtelExporterHTTPEndpoint,
		})
	}
	for _, executorInput := range executorInputs {
		executorJobSpec, err := executorInput.GenerateJobSpec()
		if err != nil {
			return "", fmt.Errorf("failed to generate executor job spec: %w", err)
		}
		ccv.Plog.Info().Msg("Generated executor job spec, writing to temporary directory as a separate file")
		filePath := filepath.Join(tempDir, fmt.Sprintf("executor-%s-job-spec.toml", executorInput.ExecutorID))
		if err := os.WriteFile(filePath, []byte(executorJobSpec), 0o644); err != nil {
			return "", fmt.Errorf("failed to write executor job spec to file: %w", err)
		}
		ccv.Plog.Info().Str("file-path", filePath).Msg("Wrote executor job spec to file")
	}

	// Aggregator config
	aggregatorInput := services.AggregatorInput{
		CommitteeName:                           committeeName,
		CommitteeVerifierResolverProxyAddresses: committeeVerifierResolverProxyAddresses,
		ThresholdPerSource:                      thresholdPerSource,
		MonitoringOtelExporterHTTPEndpoint:      monitoringOtelExporterHTTPEndpoint,
	}
	aggregatorConfig, err := aggregatorInput.GenerateConfig(verifierInputs)
	if err != nil {
		return "", fmt.Errorf("failed to generate aggregator config: %w", err)
	}
	ccv.Plog.Info().Msg("Generated aggregator config:")
	filePath := filepath.Join(tempDir, "aggregator-config.toml")
	if err := os.WriteFile(filePath, aggregatorConfig, 0o644); err != nil {
		return "", fmt.Errorf("failed to write aggregator config to file: %w", err)
	}
	ccv.Plog.Info().Str("file-path", filePath).Msg("Wrote aggregator config to file")

	if createPR {
		prURL, err := createConfigPR(gh, ctx, cldDomain, aggregatorConfig)
		if err != nil {
			return "", fmt.Errorf("failed to create config PR: %w", err)
		}
		ccv.Plog.Info().Str("pr-url", prURL).Msg("Created PR with aggregator config")
	}

	return tempDir, nil
}

func createConfigPR(gh *github.Client, ctx context.Context, cldDomain string, aggregatorConfig []byte) (string, error) {
	// Create a new branch, add the aggregator config file and open a PR
	owner := "smartcontractkit"
	repo := "infra-k8s"

	// Get repository to find default branch
	repoInfo, _, err := gh.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", fmt.Errorf("failed to fetch repository info: %w", err)
	}
	defaultBranch := repoInfo.GetDefaultBranch()

	// Create a unique branch name
	branchName := fmt.Sprintf("ccv_config_%d", time.Now().Unix())

	// Get the reference for the default branch
	baseRef, _, err := gh.Git.GetRef(ctx, owner, repo, "refs/heads/"+defaultBranch)
	if err != nil {
		return "", fmt.Errorf("failed to get base ref for branch %s: %w", defaultBranch, err)
	}

	// Create new branch ref pointing to the same commit as default
	newRef := &github.Reference{
		Ref: github.Ptr("refs/heads/" + branchName),
		Object: &github.GitObject{
			SHA: baseRef.Object.SHA,
		},
	}
	_, _, err = gh.Git.CreateRef(ctx, owner, repo, newRef)
	if err != nil {
		return "", fmt.Errorf("failed to create branch %s: %w", branchName, err)
	}

	// Path where to add the aggregator config in the repo
	aggPath := "projects/chainlink-ccv/files/aggregator/aggregator-config.yaml"

	// Create file on the new branch
	commitMsg := "Update ccv configuration"

	// Marshal aggregator config into YAML under configMap.aggregator.\.toml
	aggYaml := map[string]any{
		"stage": map[string]any{
			"main": map[string]any{
				"configMap": map[string]string{
					"aggregator.toml": string(aggregatorConfig),
				},
			},
		},
	}
	aggFileContent, err := yaml.Marshal(aggYaml)
	if err != nil {
		return "", fmt.Errorf("failed to marshal aggregator config to YAML: %w", err)
	}

	aggFile, _, _, _ := gh.Repositories.GetContents(ctx, "smartcontractkit", "infra-k8s", "projects/chainlink-ccv/files/aggregator/aggregator-config.yaml", &github.RepositoryContentGetOptions{})
	aggSHA := aggFile.GetSHA()

	opts := &github.RepositoryContentFileOptions{
		Message: github.Ptr(commitMsg),
		Content: aggFileContent,
		Branch:  github.Ptr(branchName),
		SHA:     github.Ptr(aggSHA),
	}
	_, _, err = gh.Repositories.CreateFile(ctx, owner, repo, aggPath, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create file %s on branch %s: %w", aggPath, branchName, err)
	}

	// Open a PR from the new branch into default
	prTitle := "CCV config update"
	prBody := fmt.Sprintf("CCV CLI auto-generated PR to update configuration from CLD for %s environment", cldDomain)
	newPR := &github.NewPullRequest{
		Title: github.Ptr(prTitle),
		Head:  github.Ptr(branchName),
		Base:  github.Ptr(defaultBranch),
		Body:  github.Ptr(prBody),
	}
	pr, _, err := gh.PullRequests.Create(ctx, owner, repo, newPR)
	if err != nil {
		return "", fmt.Errorf("failed to create pull request: %w", err)
	}
	return pr.GetHTMLURL(), nil
}
