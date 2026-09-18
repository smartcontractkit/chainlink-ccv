#!/usr/bin/env python3
"""Fetch a CCIPMessageSent log corpus from any EVM RPC endpoint, for use with
the differential test (CCV_DIFF_CORPUS) and for ad-hoc backtesting.

Writes the raw eth_getLogs result array as JSON. To guard against nodes that
silently drop logs (observed in the wild on public endpoints), run twice
against two independent endpoints and compare:

    python3 fetch_logs.py --rpc "$RPC_A" ... --out corpus_a.json
    python3 fetch_logs.py --rpc "$RPC_B" ... --out corpus_b.json
    python3 fetch_logs.py --compare corpus_a.json corpus_b.json

Example (Sepolia OnRamp v2.0.0):
    python3 fetch_logs.py \
        --rpc https://rpc.sepolia.ethpandaops.io \
        --address 0x181Ac7dC295f1C8C87342d07CFaBA90bC477DB5d \
        --from-block 10970571 --to-block 11522733 \
        --out sepolia_logs.json

Requires only the Python 3 standard library and curl.
"""

import argparse
import json
import subprocess
import sys
import time

# keccak256("CCIPMessageSent(uint64,address,bytes32,address,uint256,bytes,(address,uint32,uint32,uint256,bytes)[],bytes[])")
CCIP_MESSAGE_SENT_TOPIC0 = "0x371bc2ff0a006f4ef863b1d27a065d4e9f938b6d883eb154572b4aea593b32cc"


def rpc_call(rpc: str, method: str, params: list, retries: int = 4):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    body = json.dumps(payload)
    for attempt in range(retries):
        out = subprocess.run(
            ["curl", "-s", "-m", "60", "-X", "POST", rpc, "-H", "content-type: application/json", "-d", body],
            capture_output=True, text=True,
        ).stdout
        try:
            d = json.loads(out)
        except json.JSONDecodeError:
            time.sleep(1 + attempt)
            continue
        if "result" in d:
            return d["result"]
        time.sleep(1 + attempt)
    raise RuntimeError(f"{method} failed after {retries} attempts: {out[:300]}")


def fetch_logs(rpc: str, address: str, topic0: str, frm: int, to: int):
    return rpc_call(rpc, "eth_getLogs", [{
        "address": address,
        "fromBlock": hex(frm),
        "toBlock": hex(to),
        "topics": [topic0],
    }])


def scan(rpc: str, address: str, topic0: str, start: int, end: int, chunk: int):
    logs = []
    frm = start
    while frm <= end:
        to = min(frm + chunk - 1, end)
        batch = fetch_logs(rpc, address, topic0, frm, to)
        if batch:
            print(f"  {frm}-{to}: {len(batch)} logs", file=sys.stderr)
        logs.extend(batch)
        frm = to + 1
    logs.sort(key=lambda l: (int(l["blockNumber"], 16), int(l["logIndex"], 16)))
    return logs


def log_keys(logs):
    return sorted((l["transactionHash"], l["logIndex"]) for l in logs)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--compare", nargs=2, metavar=("A", "B"),
                   help="compare two corpus files instead of fetching")
    p.add_argument("--rpc", help="JSON-RPC endpoint URL")
    p.add_argument("--address", help="OnRamp contract address (0x-prefixed)")
    p.add_argument("--topic0", default=CCIP_MESSAGE_SENT_TOPIC0,
                   help="event topic0 filter (default: CCIPMessageSent v2)")
    p.add_argument("--from-block", type=lambda s: int(s, 0))
    p.add_argument("--to-block", type=lambda s: int(s, 0))
    p.add_argument("--chunk", type=int, default=5000,
                   help="block range per eth_getLogs call (keep under the endpoint's limit)")
    p.add_argument("--out", help="output JSON file (default: stdout)")
    args = p.parse_args()

    if args.compare:
        a, b = (json.load(open(f)) for f in args.compare)
        ka, kb = log_keys(a), log_keys(b)
        if ka == kb:
            print(f"OK: both corpora contain the same {len(ka)} logs")
            return
        print(f"MISMATCH: {len(a)} vs {len(b)} logs; "
              f"{len(set(ka) - set(kb))} only in A, {len(set(kb) - set(ka))} only in B",
              file=sys.stderr)
        sys.exit(1)

    missing = [n for n, v in [("--rpc", args.rpc), ("--address", args.address),
                              ("--from-block", args.from_block), ("--to-block", args.to_block)] if v is None]
    if missing:
        p.error(f"missing required: {', '.join(missing)}")

    logs = scan(args.rpc, args.address, args.topic0, args.from_block, args.to_block, args.chunk)
    print(f"total: {len(logs)} logs", file=sys.stderr)
    out = json.dumps(logs)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
