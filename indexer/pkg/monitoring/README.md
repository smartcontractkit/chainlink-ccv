# Monitoring Module

The monitoring module provides observability for the indexer service, including metrics collection, profiling, and performance monitoring. It implements the `IndexerMonitoring` interface defined in `indexer/pkg/common`.

## Overview

The monitoring module collects and exposes metrics about various aspects of the indexer's operation:
- HTTP request handling
- Storage operations (queries and writes)
- Message processing
- Resource utilization

The module is built on top of OpenTelemetry (OTEL) metrics and integrates with the Beholder client for metric collection and export. It also includes Pyroscope integration for continuous profiling.

## Architecture

The monitoring module follows a layered architecture:

```
IndexerMonitoring (interface)
    ├── IndexerBeholderMonitoring (production implementation)
    │   └── IndexerMetricLabeler (metrics recording)
    └── NoopIndexerMonitoring (testing/no-op implementation)
        └── NoopIndexerMetricLabeler (no-op metrics)
```

### Components

#### IndexerBeholderMonitoring

The production implementation that:
- Initializes the Beholder client with OTEL metric views
- Sets up global OTEL providers
- Initializes all indexer metrics
- Configures Pyroscope for continuous profiling
- Provides a metric labeler for recording metrics

#### IndexerMetricLabeler

A labeler that wraps the base metrics labeler and provides methods to record all indexer-specific metrics. It supports adding custom labels via the `With()` method, which returns a new labeler instance with the specified key-value pairs.

#### NoopIndexerMonitoring

A no-op implementation useful for testing or when monitoring is disabled. All metric recording methods are no-ops that do nothing.

