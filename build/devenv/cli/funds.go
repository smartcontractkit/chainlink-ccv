package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	chainsel "github.com/smartcontractkit/chain-selectors"

	ccv "github.com/smartcontractkit/chainlink-ccv/build/devenv"
	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// fundsCmd is the parent group: `ccv funds`.
// Persistent flags --selectors and --env are declared once here and inherited by all subcommands.
var fundsCmd = &cobra.Command{
	Use:   "funds",
	Short: "Manage native token balances across accounts",
}

// fundsDistributeCmd implements `ccv funds distribute`.
var fundsDistributeCmd = &cobra.Command{
	Use:   "distribute",
	Short: "Distribute native tokens from the primary account evenly to all other configured accounts",
	Long: `Reads all configured private keys (PRIVATE_KEY, PRIVATE_KEY_1, PRIVATE_KEY_2, ...) and
distributes the native balance of the primary deployer account (PRIVATE_KEY) evenly across all
remaining accounts on each chain. When --selectors is omitted all EVM chains found in the
environment are used. A gas reserve is withheld before splitting. Runs concurrently across chains.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		selectors, primaryAddr, recipientAddrs, chains, err := parseFundsArgs(cmd)
		if err != nil {
			return err
		}

		return runForEachChain(ctx, chains, selectors, func(ctx context.Context, chain cciptestinterfaces.Chain, selector uint64) error {
			return distributeFundsOnChain(ctx, chain, selector, primaryAddr, recipientAddrs)
		})
	},
}

// fundsReclaimCmd implements `ccv funds reclaim`.
var fundsReclaimCmd = &cobra.Command{
	Use:   "reclaim",
	Short: "Reclaim native tokens from all other configured accounts back into the primary account",
	Long: `Reads all configured private keys (PRIVATE_KEY, PRIVATE_KEY_1, PRIVATE_KEY_2, ...) and
sweeps spendable native balance from every secondary account back into the primary deployer account
on each chain. When --selectors is omitted all EVM chains in the environment are used. Accounts
with insufficient balance to cover gas are skipped with a warning. Runs concurrently across chains
and across accounts within a chain.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		selectors, primaryAddr, senderAddrs, chains, err := parseFundsArgs(cmd)
		if err != nil {
			return err
		}

		return runForEachChain(ctx, chains, selectors, func(ctx context.Context, chain cciptestinterfaces.Chain, selector uint64) error {
			return reclaimFundsOnChain(ctx, chain, selector, primaryAddr, senderAddrs)
		})
	},
}

// fundsBalancesCmd implements `ccv funds balances`.
var fundsBalancesCmd = &cobra.Command{
	Use:   "balances",
	Short: "Display the current native token balances for all configured accounts",
	Long: `Queries the native balance of every configured account (PRIVATE_KEY,
PRIVATE_KEY_1, PRIVATE_KEY_2, ...) concurrently across all selected EVM chains
and prints the results as a sorted table. Chains are sorted by selector; within
each chain the primary account is listed first, followed by user accounts in order.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		selectors, primaryAddr, secondaryAddrs, chains, err := parseFundsArgs(cmd)
		if err != nil {
			return err
		}

		return printBalanceTable(ctx, cmd.OutOrStdout(), chains, selectors, primaryAddr, secondaryAddrs)
	},
}

// parseFundsArgs reads the inherited persistent flags, builds the CLDF environment (including all
// chain clients), resolves chain selectors (falling back to every EVM chain in the environment when
// --selectors is unset), and derives addresses for the primary and secondary accounts.
//
// Returns:
//   - selectors: resolved chain selectors to operate on
//   - primaryAddr: address of the primary/deployer account (from PRIVATE_KEY)
//   - senderAddrs: addresses of all secondary accounts (from PRIVATE_KEY_1, PRIVATE_KEY_2, ...)
//   - chains: fully initialized chain implementations indexed by selector
func parseFundsArgs(cmd *cobra.Command) (
	selectors []uint64,
	primaryAddr protocol.UnknownAddress,
	senderAddrs []protocol.UnknownAddress,
	chains map[uint64]cciptestinterfaces.CCIP17,
	err error,
) {
	chainSelectorsStr, err := cmd.Flags().GetString("selectors")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse selectors flag: %w", err)
	}

	envName, err := cmd.Flags().GetString("env")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse env flag: %w", err)
	}

	// Build the library early: this constructs all chain clients (via NewCLDFOperationsEnvironment)
	// and makes them available through the Chain interface. Only EVM chains are loaded since native
	// token transfers are an EVM-specific concept.
	lib, err := ccv.NewLib(&ccv.Plog, fmt.Sprintf("env-%s.toml", envName), chainsel.FamilyEVM)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to initialise environment: %w", err)
	}

	chains, err = lib.ChainsMap(cmd.Context())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to build chain implementations: %w", err)
	}

	if chainSelectorsStr == "" {
		// Fall back to every chain loaded from the environment.
		selectors = make([]uint64, 0, len(chains))
		for sel := range chains {
			selectors = append(selectors, sel)
		}
		if len(selectors) == 0 {
			return nil, nil, nil, nil, fmt.Errorf("no EVM chains found in environment")
		}
	} else {
		selectors, err = parseSelectors(chainSelectorsStr)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		// Validate all requested selectors exist in the environment.
		for _, sel := range selectors {
			if _, ok := chains[sel]; !ok {
				return nil, nil, nil, nil, fmt.Errorf(
					"chain selector %d not found in environment; verify the env file or the provided selectors", sel,
				)
			}
		}
	}

	// Derive addresses from private keys. Private keys are not forwarded into any transfer logic;
	// they are only used here to identify which addresses correspond to configured accounts.
	allKeys := ccv.GetUserPrivateKeys()
	if len(allKeys) < 1 {
		return nil, nil, nil, nil, fmt.Errorf("PRIVATE_KEY must be set")
	}

	primaryPriv, err := crypto.HexToECDSA(strings.TrimPrefix(allKeys[0], "0x"))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse primary private key: %w", err)
	}
	primaryAddr = protocol.UnknownAddress(crypto.PubkeyToAddress(primaryPriv.PublicKey).Bytes())

	// Derive addresses for all secondary accounts up-front so key-parsing failures surface before
	// any on-chain work begins.
	senderAddrs = make([]protocol.UnknownAddress, 0, len(allKeys)-1)
	for i, pk := range allKeys[1:] {
		privKey, err := crypto.HexToECDSA(strings.TrimPrefix(pk, "0x"))
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to parse private key at index %d: %w", i+1, err)
		}
		senderAddrs = append(senderAddrs, protocol.UnknownAddress(crypto.PubkeyToAddress(privKey.PublicKey).Bytes()))
	}

	return selectors, primaryAddr, senderAddrs, chains, nil
}

// distributeFundsOnChain transfers an equal share of the primary account's native balance to each
// recipient. The amount is computed as balance/N; the EVM automatically deducts gas from the
// sender's remaining balance, so a small dust amount may stay in the primary account after all
// transfers complete.
func distributeFundsOnChain(
	ctx context.Context,
	chain cciptestinterfaces.Chain,
	selector uint64,
	primaryAddr protocol.UnknownAddress,
	recipients []protocol.UnknownAddress,
) error {
	if len(recipients) == 0 {
		return fmt.Errorf("no recipient addresses provided")
	}

	// Query balances for every account (primary first, then recipients) concurrently.
	allAddrs := append([]protocol.UnknownAddress{primaryAddr}, recipients...)
	balances := make([]*big.Int, len(allAddrs))

	var mu sync.Mutex
	g, gCtx := errgroup.WithContext(ctx)
	for i, addr := range allAddrs {
		g.Go(func() error {
			bal, err := chain.NativeBalance(gCtx, addr)
			if err != nil {
				return fmt.Errorf("failed to query balance for %s on chain selector %d: %w",
					common.BytesToAddress(addr).Hex(), selector, err)
			}
			mu.Lock()
			balances[i] = bal
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	// Target = total balance across all accounts / number of accounts.
	// This is the ideal per-account balance if funds were perfectly distributed.
	total := new(big.Int)
	for _, bal := range balances {
		total.Add(total, bal)
	}
	if total.Sign() == 0 {
		return fmt.Errorf("total balance across all accounts is zero on chain selector %d", selector)
	}
	target := new(big.Int).Div(total, big.NewInt(int64(len(allAddrs))))

	// Accounts at or above 75% of the target are considered adequately funded and are skipped.
	threshold := new(big.Int).Mul(target, big.NewInt(75))
	threshold.Div(threshold, big.NewInt(100))

	ccv.Plog.Info().
		Uint64("chainSelector", selector).
		Str("primaryAddress", common.BytesToAddress(primaryAddr).Hex()).
		Str("totalWei", total.String()).
		Str("targetWei", target.String()).
		Str("thresholdWei", threshold.String()).
		Int("accounts", len(allAddrs)).
		Msg("Computing native fund distribution")

	// Collect accounts that fall below the threshold and the amount each needs to reach target.
	type fundingOp struct {
		addr   protocol.UnknownAddress
		needed *big.Int
	}
	ops := make([]fundingOp, 0, len(recipients))
	for i, recipient := range recipients {
		recipientBal := balances[i+1] // balances[0] is primary
		if recipientBal.Cmp(threshold) >= 0 {
			ccv.Plog.Info().
				Uint64("chainSelector", selector).
				Str("address", common.BytesToAddress(recipient).Hex()).
				Str("balanceWei", recipientBal.String()).
				Str("thresholdWei", threshold.String()).
				Msg("Account adequately funded; skipping")
			continue
		}
		ops = append(ops, fundingOp{recipient, new(big.Int).Sub(target, recipientBal)})
	}

	if len(ops) == 0 {
		ccv.Plog.Info().
			Uint64("chainSelector", selector).
			Msg("All accounts are adequately funded; nothing to distribute")
		return nil
	}

	// Verify the primary account can cover all top-ups with a 10% gas buffer.
	totalNeeded := new(big.Int)
	for _, op := range ops {
		totalNeeded.Add(totalNeeded, op.needed)
	}
	primaryBalance := balances[0]
	available := new(big.Int).Mul(primaryBalance, big.NewInt(90))
	available.Div(available, big.NewInt(100))
	if available.Cmp(totalNeeded) < 0 {
		return fmt.Errorf(
			"primary account %s has insufficient balance on chain selector %d: "+
				"%.6f ETH available (90%% of balance), %.6f ETH needed to top up %d account(s)",
			common.BytesToAddress(primaryAddr).Hex(), selector,
			weiToETH(available), weiToETH(totalNeeded), len(ops),
		)
	}

	// Top up each under-funded account to the target balance.
	for _, op := range ops {
		ccv.Plog.Info().
			Uint64("chainSelector", selector).
			Str("recipient", common.BytesToAddress(op.addr).Hex()).
			Str("amountWei", op.needed.String()).
			Str("targetWei", target.String()).
			Msg("Topping up account to target balance")

		if err := chain.TransferNative(ctx, primaryAddr, op.addr, op.needed); err != nil {
			return fmt.Errorf("failed to top up %s on chain selector %d: %w",
				common.BytesToAddress(op.addr).Hex(), selector, err)
		}
	}

	ccv.Plog.Info().
		Uint64("chainSelector", selector).
		Int("funded", len(ops)).
		Int("skipped", len(recipients)-len(ops)).
		Str("targetWei", target.String()).
		Msg("Native fund distribution complete")

	return nil
}

// reclaimFundsOnChain sweeps the full spendable native balance from each secondary account back
// into the primary account. TransferNative is called with a nil amount so it computes the gas cost
// internally and transfers the remainder. Accounts whose balance cannot cover gas are skipped with
// a warning. All senders are drained concurrently and every sender is always attempted regardless
// of failures on other accounts; all errors are aggregated and returned together.
func reclaimFundsOnChain(
	ctx context.Context,
	chain cciptestinterfaces.Chain,
	selector uint64,
	primaryAddr protocol.UnknownAddress,
	senders []protocol.UnknownAddress,
) error {
	if len(senders) == 0 {
		return fmt.Errorf("no sender addresses provided")
	}

	ccv.Plog.Info().
		Uint64("chainSelector", selector).
		Str("primaryAddress", common.BytesToAddress(primaryAddr).Hex()).
		Int("senders", len(senders)).
		Msg("Reclaiming native funds")

	var (
		wg     sync.WaitGroup
		errsMu sync.Mutex
		errs   []error
	)
	for _, senderAddr := range senders {
		wg.Go(func() {
			err := chain.TransferNative(ctx, senderAddr, primaryAddr, nil)
			if errors.Is(err, cciptestinterfaces.ErrInsufficientNativeBalance) {
				ccv.Plog.Warn().
					Uint64("chainSelector", selector).
					Str("senderAddress", common.BytesToAddress(senderAddr).Hex()).
					Err(err).
					Msg("Sender balance too low to cover gas; skipping reclaim")
				return
			}
			if err != nil {
				errsMu.Lock()
				errs = append(errs, fmt.Errorf("failed to reclaim from %s on chain selector %d: %w",
					common.BytesToAddress(senderAddr).Hex(), selector, err))
				errsMu.Unlock()
			}
		})
	}
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		return err
	}

	ccv.Plog.Info().
		Uint64("chainSelector", selector).
		Int("senders", len(senders)).
		Str("primaryAddress", common.BytesToAddress(primaryAddr).Hex()).
		Msg("Native fund reclaim complete")

	return nil
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

// runForEachChain fans out fn concurrently across every chain in selectors. Every chain is always
// attempted regardless of failures on sibling chains; all errors are aggregated via errors.Join.
func runForEachChain(
	ctx context.Context,
	chains map[uint64]cciptestinterfaces.CCIP17,
	selectors []uint64,
	fn func(context.Context, cciptestinterfaces.Chain, uint64) error,
) error {
	var (
		wg     sync.WaitGroup
		errsMu sync.Mutex
		errs   []error
	)
	for _, selector := range selectors {
		impl, ok := chains[selector]
		if !ok {
			return fmt.Errorf("chain selector %d not found in the loaded environment", selector)
		}
		wg.Go(func() {
			if err := fn(ctx, impl, selector); err != nil {
				errsMu.Lock()
				errs = append(errs, fmt.Errorf("chain selector %d: %w", selector, err))
				errsMu.Unlock()
			}
		})
	}
	wg.Wait()
	return errors.Join(errs...)
}

// accountBalance holds the fetched native balance for one account on one chain.
type accountBalance struct {
	selector   uint64
	roleOrder  int // 0 = primary, 1+ = user-N; used for sort stability
	address    common.Address
	role       string
	balanceWei *big.Int
}

// printBalanceTable fetches native balances for all accounts on all chains concurrently and
// renders them as an aligned table to out. Rows are sorted by chain selector (ascending) then
// by role (primary first, then user-1, user-2, …). Chains are visually separated by a blank row.
func printBalanceTable(
	ctx context.Context,
	out io.Writer,
	chains map[uint64]cciptestinterfaces.CCIP17,
	selectors []uint64,
	primaryAddr protocol.UnknownAddress,
	secondaryAddrs []protocol.UnknownAddress,
) error {
	type addrEntry struct {
		addr  protocol.UnknownAddress
		role  string
		order int
	}

	accounts := make([]addrEntry, 0, 1+len(secondaryAddrs))
	accounts = append(accounts, addrEntry{primaryAddr, "primary", 0})
	for i, addr := range secondaryAddrs {
		accounts = append(accounts, addrEntry{addr, fmt.Sprintf("user-%d", i+1), i + 1})
	}

	var mu sync.Mutex
	var rows []accountBalance

	g, gCtx := errgroup.WithContext(ctx)
	for _, selector := range selectors {
		chain := chains[selector]
		for _, acct := range accounts {
			g.Go(func() error {
				balance, err := chain.NativeBalance(gCtx, acct.addr)
				if err != nil {
					return fmt.Errorf("failed to query balance for %s on chain selector %d: %w",
						common.BytesToAddress(acct.addr).Hex(), selector, err)
				}
				mu.Lock()
				rows = append(rows, accountBalance{
					selector:   selector,
					roleOrder:  acct.order,
					address:    common.BytesToAddress(acct.addr),
					role:       acct.role,
					balanceWei: balance,
				})
				mu.Unlock()
				return nil
			})
		}
	}
	if err := g.Wait(); err != nil {
		return err
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].selector != rows[j].selector {
			return rows[i].selector < rows[j].selector
		}
		return rows[i].roleOrder < rows[j].roleOrder
	})

	const (
		colSep     = "────────────────────"
		colChain   = "────────────────────────"
		colAddress = "──────────────────────────────────────────"
		colRole    = "──────────"
		colBalance = "──────────────────"
	)

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SELECTOR\tCHAIN\tADDRESS\tROLE\tBALANCE (ETH)\t")
	fmt.Fprintln(w, colSep+"\t"+colChain+"\t"+colAddress+"\t"+colRole+"\t"+colBalance+"\t")

	prevSelector := uint64(0)
	for i, row := range rows {
		// Blank separator between chain groups (after the first group).
		if row.selector != prevSelector && i > 0 {
			fmt.Fprintln(w, "\t\t\t\t\t")
		}

		selectorStr, chainName := "", ""
		if row.selector != prevSelector {
			selectorStr = fmt.Sprintf("%d", row.selector)
			chainName = chainDisplayName(row.selector)
			prevSelector = row.selector
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%.6f\t\n",
			selectorStr, chainName, row.address.Hex(), row.role, weiToETH(row.balanceWei))
	}

	return w.Flush()
}

// chainDisplayName returns a human-readable name for the given chain selector,
// falling back to the numeric selector string if the name cannot be resolved.
func chainDisplayName(selector uint64) string {
	if c, ok := chainsel.ChainBySelector(selector); ok {
		return c.Name
	}
	return fmt.Sprintf("%d", selector)
}

// weiToETH converts a wei amount to a float64 ETH value for display purposes.
func weiToETH(wei *big.Int) float64 {
	if wei == nil || wei.Sign() == 0 {
		return 0
	}
	eth, _ := new(big.Float).Quo(
		new(big.Float).SetInt(wei),
		new(big.Float).SetPrec(256).SetInt(big.NewInt(1_000_000_000_000_000_000)),
	).Float64()
	return eth
}

// parseSelectors splits a comma-separated string of chain selectors into a []uint64.
func parseSelectors(raw string) ([]uint64, error) {
	parts := strings.Split(raw, ",")
	selectors := make([]uint64, 0, len(parts))
	for _, part := range parts {
		sel, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chain selector %q: %w", strings.TrimSpace(part), err)
		}
		selectors = append(selectors, sel)
	}
	return selectors, nil
}
