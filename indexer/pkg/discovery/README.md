# Discovery

The discovery module provides components for discovering CCV messages and off-chain storage readers. It implements two discovery patterns: `MessageDiscovery` for discovering messages from a trusted source. 

### MessageDiscovery

`MessageDiscovery` is a critical part of the indexer, it's goal is to find new CCIP messages to start processing. To avoid potentional attack vectors we use a trusted discovery source.

It polls the discovery source at a configurable interval (`PollInterval`) to retrieve new messages and emits discovered messages via a buffered channel for downstream consumption.

As `MessageDiscovery` uses the `ResilientReader` if the upstream discovery source is down the circuit breaker will trip and reconnect once the discovery source is back up.

> Note: The `AggregatorMessageDiscovery` implementation also persists the VerificationResult to avoid additional calls to the aggregator

### Configuration

- `PollInterval`: How often to poll the aggregator
- `Timeout`: Maximum duration for a single polling operation
- `MessageChannelSize`: Buffer size for the message channel

### Usage

```go
discovery, err := NewAggregatorMessageDiscovery(
    WithLogger(logger),
    WithMonitoring(monitoring),
    WithStorage(storage),
    WithAggregator(resilientReader),
    WithConfig(config),
)

messageCh := discovery.Start(ctx)
defer discovery.Close()

for msg := range messageCh {
    // Process discovered message...
}
```

