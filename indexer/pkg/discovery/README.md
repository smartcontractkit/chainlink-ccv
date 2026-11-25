# Discovery

The discovery module provides components for discovering CCV messages and off-chain storage readers. 

- `MessageDiscovery` for discovering messages from a trusted source. 

### MessageDiscovery

`MessageDiscovery` is a critical part of the indexer, it's goal is to find new CCIP messages to start processing. To avoid potentional attack vectors we use a trusted discovery source.

It polls the discovery source at a configurable interval (`PollInterval`) to retrieve new messages. It persists each batch with each new message in the `PROCESSING` status. The worker pool on every replica claims due `PROCESSING` messages from the database.

As `MessageDiscovery` uses the `ResilientReader` if the upstream discovery source is down the circuit breaker will trip and reconnect once the discovery source is back up.

> Note: The `AggregatorMessageDiscovery` implementation also persists the VerificationResult to avoid additional calls to the aggregator

### Configuration

- `PollInterval`: How often to poll the aggregator
- `Timeout`: Maximum duration for a single polling operation

### Usage

```go
discovery, err := NewAggregatorMessageDiscovery(
    WithLogger(logger),
    WithMonitoring(monitoring),
    WithStorage(storage),
    WithAggregator(resilientReader),
    WithConfig(config),
)

discovery.Start(ctx) // persists messages for the worker pool
defer discovery.Close()
```

