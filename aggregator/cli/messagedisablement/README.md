# Message Disablement Rules CLI

The `message-disablement-rules` CLI manages aggregator-side rules that reject
matching messages before signature validation, storage, or aggregation work.
Rules are active while they exist in the aggregator database. Deleting a rule is
the enable operation for the traffic it matched.

The aggregator refreshes active rules from the database on its configured
`messageDisablementRules.refreshInterval`, so rule changes are not guaranteed to
take effect until the next refresh.

## Commands

Run commands through the aggregator binary:

```sh
aggregator message-disablement-rules list
aggregator message-disablement-rules list --type Chain
aggregator message-disablement-rules get --id <uuid>
aggregator message-disablement-rules delete --id <uuid>
```

Create commands print a stable `id=<uuid>` line for scripts and tests.

```sh
aggregator message-disablement-rules create chain --chain <selector>
aggregator message-disablement-rules create lane --lane <selector_a>,<selector_b>
aggregator message-disablement-rules create token --token <selector>,<token_address>
```

`--chain` may be repeated or comma-separated to create multiple Chain rules.
`--lane` and `--token` may be repeated to create multiple rules. Chain selectors
are parsed as unsigned 64-bit decimal integers. Token addresses are normalized
to lowercase `0x...` hex.

## Rule Effects

### Chain

A Chain rule disables any message where either side touches the configured chain
selector.

```sh
aggregator message-disablement-rules create chain --chain 3379446385462418246
```

Effect:

- source selector `3379446385462418246` -> blocked
- destination selector `3379446385462418246` -> blocked
- unrelated source and destination selectors -> allowed

### Lane

A Lane rule disables messages between two selectors in either direction. The
selector pair is unordered.

```sh
aggregator message-disablement-rules create lane --lane 3379446385462418246,909606746561742123
```

Effect:

- `3379446385462418246 -> 909606746561742123` -> blocked
- `909606746561742123 -> 3379446385462418246` -> blocked
- either chain paired with any other selector -> allowed unless another rule matches

### Token

A Token rule disables token-transfer messages that touch the configured
chain/token pair on the same side of the message. Matching is strict:
source selector is checked only against source token, and destination selector
is checked only against destination token.

```sh
aggregator message-disablement-rules create token --token 3379446385462418246,0xabc123
```

Effect:

- source selector and source token match the rule -> blocked
- destination selector and destination token match the rule -> blocked
- destination selector and source token match the rule -> allowed unless another rule matches
- source selector and destination token match the rule -> allowed unless another rule matches
- non-token messages -> allowed unless a Chain or Lane rule matches
- token-transfer messages using the token on another chain -> allowed unless another rule matches

## Re-Enabling Traffic

Delete the rule to re-enable matching traffic:

```sh
aggregator message-disablement-rules delete --id <uuid>
```

Traffic resumes after the aggregator successfully refreshes its in-memory rule
registry.
