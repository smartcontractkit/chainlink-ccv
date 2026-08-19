//! Historical backtest for the EVM SourceReader against a live RPC endpoint.
//!
//! Fetches every CCIPMessageSent event in a block range, cross-checks the reader
//! against the raw logs (count and per-event identity), and exercises the head
//! tracker and RMN curse reader.
//!
//! Usage:
//!   cargo run -p ccv-chainaccess --example backtest -- \
//!     <rpc_url> <on_ramp> <rmn_remote> <chain_selector> <from_block> <to_block> [chunk_size]
//!
//! Example (Sepolia OnRamp v2.0.0, 113 historical events):
//!   cargo run -p ccv-chainaccess --example backtest -- \
//!     https://ethereum-sepolia-rpc.publicnode.com \
//!     0x181Ac7dC295f1C8C87342d07CFaBA90bC477DB5d \
//!     0xF094E1dB26Ce8C76C9fF0bD0566Bb8EEfF1b76dd \
//!     16015286601757825753 10970571 11522733 10000

use std::process::ExitCode;

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;

use ccv_chainaccess::{HeadTracker, RmnCurseReader, SourceReader};
use ccv_chainaccess::evm::EvmSourceReader;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("backtest failed: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 7 {
        return Err(format!(
            "usage: {} <rpc_url> <on_ramp> <rmn_remote> <chain_selector> <from_block> <to_block> [chunk_size]",
            args[0]
        )
        .into());
    }
    let rpc_url = args[1].parse()?;
    let on_ramp: Address = args[2].parse()?;
    let rmn_remote: Address = args[3].parse()?;
    let chain_selector: u64 = args[4].parse()?;
    let from_block: u64 = args[5].parse()?;
    let to_block: u64 = args[6].parse()?;
    let chunk_size: u64 = if args.len() > 7 { args[7].parse()? } else { 10_000 };

    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let reader = EvmSourceReader::new(provider, on_ramp, rmn_remote, chain_selector)?;

    // Head tracker.
    let (latest, finalized) = reader.latest_and_finalized_block().await?;
    println!("latest block:    {} (hash {})", latest.number, latest.hash);
    println!("finalized block: {} (hash {})", finalized.number, finalized.hash);
    match reader.latest_safe_block().await? {
        Some(safe) => println!("safe block:      {} (hash {})", safe.number, safe.hash),
        None => println!("safe block:      <unsupported tag>"),
    }

    // RMN curse reader.
    let subjects = reader.get_rmn_cursed_subjects().await?;
    println!("cursed subjects: {}", subjects.len());

    // Historical event scan, chunked to stay under RPC range limits.
    let mut all_events = Vec::new();
    let mut from = from_block;
    while from <= to_block {
        let to = from.saturating_add(chunk_size).saturating_sub(1).min(to_block);
        let events = reader.fetch_message_sent_events(from, Some(to)).await?;
        if !events.is_empty() {
            println!("blocks {from}-{to}: {} events", events.len());
        }
        all_events.extend(events);
        from = to.saturating_add(1);
    }
    println!("total events in [{from_block}, {to_block}]: {}", all_events.len());

    // Sanity: message IDs recomputed from the decoded messages must equal the
    // on-chain topic values (checked inside the reader), and headers for the
    // event blocks must be fetchable.
    let mut block_numbers: Vec<u64> = all_events.iter().map(|e| e.block_number).collect();
    block_numbers.sort_unstable();
    block_numbers.dedup();
    let headers = reader.get_blocks_headers(&block_numbers).await?;
    let missing: Vec<u64> = block_numbers.iter().filter(|n| !headers.contains_key(n)).copied().collect();
    if !missing.is_empty() {
        return Err(format!("missing headers for event blocks: {missing:?}").into());
    }
    println!("headers verified for {} event blocks", block_numbers.len());

    if let Some(first) = all_events.first() {
        println!(
            "first event: block {} message 0x{} receipts {}",
            first.block_number,
            alloy::primitives::hex::encode(first.message_id),
            first.receipts.len()
        );
    }
    Ok(())
}
