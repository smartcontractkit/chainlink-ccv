package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/c-bata/go-prompt"
)

const (
	historyFileName = "shell_history"
	activeFileName  = "active_config"
)

func getCommands() []prompt.Suggest {
	activeConfig := getActiveConfig()
	if activeConfig == "" {
		activeConfig = "default"
	}

	return []prompt.Suggest{
		{Text: "", Description: "Choose command, press <space> for more options after selecting command"},
		{Text: "up", Description: "Spin up the development environment [active config: " + activeConfig + "]"},
		{Text: "down", Description: "Tear down the development environment"},
		{Text: "restart", Description: "Restart the development environment [active config: " + activeConfig + "]"},
		{Text: "test", Description: "Perform smoke or load/chaos testing"},
		{Text: "bs", Description: "Manage the Blockscout EVM block explorer"},
		{Text: "obs", Description: "Manage the observability stack"},
		{Text: "db", Description: "Inspect Databases"},
		{Text: "upload-on-chain-metrics", Description: "Temporarily serves all on-chain metrics as a Prometheus metrics endpoint so they can be scraped"},
		{Text: "exit", Description: "Exit the interactive shell"},
		{Text: "deploy-commit-contracts", Description: "Deploy contracts for a new commit verifier"},
		{Text: "deploy-mock-receiver", Description: "Deploy a mock receiver contract to a given chain selector with a specific config"},
		{Text: "send", Description: "Send an example CCIP ArgsV2/V3 message from one chain to another"},
	}
}

func getSubCommands(parent string) []prompt.Suggest {
	switch parent {
	case "send":
		return []prompt.Suggest{
			{Text: "Chain selectors", Description: "V2: source,destination or V3: source,destination,finality"},
			{Text: "3379446385462418246,12922642891491394802", Description: "V2: send default Anvil 1337 -> Anvil 2337"},
			{Text: "12922642891491394802,3379446385462418246", Description: "V2: send default Anvil 1337 <- Anvil 2337"},
			{Text: "3379446385462418246,12922642891491394802,12", Description: "V3: send Anvil 1337 -> Anvil 2337 with finality=12"},
			{Text: "12922642891491394802,3379446385462418246,5", Description: "V3: send Anvil 1337 <- Anvil 2337 with finality=5"},
		}
	case "deploy-commit-contracts":
		return []prompt.Suggest{
			{Text: "<threshold>,<signer1>,<signer2>,...", Description: "Deploy contracts for a new commit verifier across all chains with a signature quorum (i.e. 3,0xabc...,0xdef...,0xghi...)"},
		}
	case "deploy-mock-receiver":
		return []prompt.Suggest{
			{Text: "<chainSelector>,<ccv_offramp1>;<ccv_offramp2>,<optionalThreshold>,<ccv_offramp3>;<ccv_offramp4>", Description: "Deploy a mock receiver contract to a given chain selector with a specific config (i.e. 3379446385462418246,0xabc...,1,0xdef...)"},
		}
	case "test":
		return []prompt.Suggest{
			{Text: "smoke", Description: "Send all the example messages between 1337 <> 2337"},
			{Text: "smoke-v2", Description: "Send an example ArgsV2 message between 1337 <> 2337 local Anvil chains (EVM)"},
			{Text: "smoke-v3", Description: "Send an example ArgsV2 message between 1337 <> 2337 local Anvil chains (EVM)"},
			{Text: "load", Description: "Run the default load test (1msg/s) 1337 -> 2337 local Anvil chain (EVM)"},
			{Text: "rpc-latency", Description: "Default load test + 400ms RPC latency (all chains)"},
			{Text: "gas-spikes", Description: "Default load test + slow and fast gas spikes"},
			{Text: "reorgs", Description: "Default load test + reorgs (Requires 'up env.toml,env-geth.toml' environment"},
			{Text: "chaos", Description: "Default load test + chaos (restarts, latency, data loss between services)"},
			{Text: "indexer-load", Description: "Indexer Load Test (50msg/s)"},
		}
	case "addresses":
		return []prompt.Suggest{
			{Text: "addresses", Description: "Print all smart-contract addresses data (CLDF)"},
		}
	case "bs":
		return []prompt.Suggest{
			{Text: "up", Description: "Spin up Blockscout and listen to dst chain (8555)"},
			{Text: "up -u http://host.docker.internal:8545 -c 1337", Description: "Spin up Blockscout and listen to src chain (8545)"},
			{Text: "down", Description: "Remove Blockscout stack"},
			{Text: "restart", Description: "Restart Blockscout and listen to dst chain (8555)"},
			{Text: "restart -u http://host.docker.internal:8545 -c 1337", Description: "Restart Blockscout and listen to src chain (8545)"},
		}
	case "obs":
		return []prompt.Suggest{
			{Text: "up", Description: "Spin up observability stack (Loki/Prometheus/Grafana)"},
			{Text: "up -m full", Description: "Spin up full observability stack (Pyroscope, cadvisor, postgres exporter)"},
			{Text: "up -m loki", Description: "Spin up Loki + Grafana (only for log assertions in CI)"},
			{Text: "down", Description: "Spin down observability stack"},
			{Text: "restart -m full", Description: "Restart full observability stack"},
			{Text: "restart -m loki", Description: "Restart only Loki observability stack"},
			{Text: "restart", Description: "Restart observability stack"},
		}
	case "db":
		return []prompt.Suggest{
			{Text: "", Description: "Press <space> for more options"},
			{Text: "indexer", Description: "Inspect Indexer Database"},
			{Text: "aggregator", Description: "Inspect Aggregator Database"},
			{Text: "verifier", Description: "Inspect Verifier Database"},
		}
	case "u":
		fallthrough
	case "up":
		fallthrough
	case "r":
		fallthrough
	case "restart":
		return []prompt.Suggest{
			{Text: "env-single-node.toml", Description: "Spin up Anvil <> Anvil local chains, 1 CL node"},
			{Text: "env.toml,env-single-node.toml,env-single-node-rebuild.toml", Description: "(Rebuild local CL Docker image) Spin up Anvil <> Anvil local chains, all services, 1 CL nodes"},
			{Text: "env.toml", Description: "Spin up Anvil <> Anvil local chains, all services, 4 CL nodes"},
			{Text: "env.toml,env-cl-rebuild.toml", Description: "(Rebuild local CL Docker image) Spin up Anvil <> Anvil local chains, all services, 4 CL nodes"},
			{Text: "env.toml,env-geth.toml", Description: "Spin up Geth <> Geth local chains (clique), all services, 4 CL nodes"},
			{Text: "env.toml,env-fuji-fantom.toml", Description: "Spin up testnets: Fuji <> Fantom, all services, 4 CL nodes"},
		}
	default:
		return []prompt.Suggest{}
	}
}

func executor(in string) {
	checkDockerIsRunning()
	in = strings.TrimSpace(in)
	if in == "" {
		return
	}
	if in == "exit" {
		fmt.Println("Goodbye!")
		os.Exit(0)
	}

	restart := "restart"
	// Save active config for "up" and "restart" commands if provided.
	if strings.HasPrefix(in, "up ") {
		saveActiveConfig(in[3:])
		in = "up"
	} else if strings.HasPrefix(in, "u ") {
		saveActiveConfig(in[2:])
		in = "up"
	} else if strings.HasPrefix(in, "restart ") {
		saveActiveConfig(in[8:])
		in = restart
	} else if strings.HasPrefix(in, "r ") {
		saveActiveConfig(in[2:])
		in = restart
	}

	switch in {
	// append active config to "up" and "restart" commands.
	case "up", "u", restart, "r":
		in = fmt.Sprintf("%s %s", in, getActiveConfig())
	}

	// don't save "exit" or empty lines to history
	saveHistory(in)

	args := strings.Fields(in)
	os.Args = append([]string{"ccv"}, args...)
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

// completer provides autocomplete suggestions for multi-word commands.
func completer(in prompt.Document) []prompt.Suggest {
	text := in.TextBeforeCursor()
	words := strings.Fields(text)
	lastCharIsSpace := len(text) > 0 && text[len(text)-1] == ' '

	switch {
	case len(words) == 0:
		return getCommands()
	case len(words) == 1:
		if lastCharIsSpace {
			return getSubCommands(words[0])
		} else {
			return prompt.FilterHasPrefix(getCommands(), words[0], true)
		}

	case len(words) >= 2:
		if lastCharIsSpace {
			return []prompt.Suggest{}
		} else {
			parent := words[0]
			currentWord := words[len(words)-1]
			return prompt.FilterHasPrefix(getSubCommands(parent), currentWord, true)
		}
	default:
		return []prompt.Suggest{}
	}
}

// resetTerm resets terminal settings to Unix defaults.
func resetTerm() {
	cmd := exec.Command("stty", "sane")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func StartShell() {
	defer resetTerm()
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("ccv> "),
		prompt.OptionPrefixTextColor(prompt.Yellow),
		prompt.OptionTitle("CCIP Interactive Shell"),
		prompt.OptionMaxSuggestion(15),
		prompt.OptionShowCompletionAtStart(),
		prompt.OptionCompletionWordSeparator(" "),
		prompt.OptionSelectedSuggestionBGColor(prompt.LightGray),
		prompt.OptionSelectedSuggestionTextColor(prompt.Black),
		prompt.OptionDescriptionBGColor(prompt.DarkGray),
		prompt.OptionDescriptionTextColor(prompt.White),
		prompt.OptionSuggestionBGColor(prompt.Black),
		prompt.OptionSuggestionTextColor(prompt.Green),
		prompt.OptionScrollbarThumbColor(prompt.DarkGray),
		prompt.OptionScrollbarBGColor(prompt.Black),
		prompt.OptionAddKeyBind(prompt.KeyBind{
			Key: prompt.ControlC,
			Fn: func(buf *prompt.Buffer) {
				fmt.Println("Interrupted, exiting...")
				resetTerm()
				os.Exit(0)
			},
		}),
		prompt.OptionHistory(getHistory()),
	)
	p.Run()
}
