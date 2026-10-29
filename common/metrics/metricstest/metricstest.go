// Package metricstest snapshots the OTel instruments that code creates and compares them with a golden file.
// The registry in tools/metricsgolden/registry uses it for all services.
package metricstest

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/smartcontractkit/chainlink-ccv/common/metrics/metricsgolden"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// UpdateEnv is the environment variable that makes AssertGolden write the golden file.
const UpdateEnv = "UPDATE_METRICS_GOLDEN"

// Snapshot runs exercise with a recording beholder meter and returns each instrument it created.
// It fails if exercise records no value on an instrument, because its labels are then unknown.
// List instruments that no code records in unrecorded; they are kept with no labels.
func Snapshot(t *testing.T, views []sdkmetric.View, exercise func(), unrecorded ...string) []metricsgolden.Metric {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithView(views...))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	rec := &recordingMeter{Meter: provider.Meter("metricstest"), created: make(map[string]metricsgolden.Metric)}

	prev := beholder.GetClient()
	client := *beholder.NewNoopClient()
	client.Meter = rec
	beholder.SetClient(&client)
	defer beholder.SetClient(prev)

	exercise()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	recorded := make(map[string]metricdata.Metrics)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			recorded[m.Name] = m
		}
	}

	out := make([]metricsgolden.Metric, 0, len(rec.created))
	for name, m := range rec.created {
		data, ok := recorded[name]
		if !ok && slices.Contains(unrecorded, name) {
			out = append(out, m)
			continue
		}
		if !ok {
			t.Errorf("instrument %q is created but no value is recorded: call the method that records it", name)
			continue
		}
		m.Labels, m.Buckets = labelsAndBuckets(data.Data)
		out = append(out, m)
	}
	return metricsgolden.Normalize(out)
}

// AssertGolden compares got with the golden file at path. With UPDATE_METRICS_GOLDEN=1, it writes the file.
func AssertGolden(t *testing.T, path string, got metricsgolden.File) {
	t.Helper()

	b, err := metricsgolden.Marshal(got)
	require.NoError(t, err)

	if os.Getenv(UpdateEnv) != "" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, b, 0o600))
		return
	}

	want, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err, "golden file missing: run the test with %s=1", UpdateEnv)
	if string(want) == string(b) {
		return
	}
	wantFile, err := metricsgolden.Parse(want)
	require.NoError(t, err)
	for _, v := range metricsgolden.Compare(wantFile, got) {
		t.Errorf("breaking change: %s", v)
	}
	t.Errorf("metrics differ from %s: run 'just metrics-golden-update' and review the diff", path)
}

// CallAll calls each exported method of target one time with zero-value arguments and t.Context() for a context.
// Use it to record a value on each instrument. args overrides the arguments of a method by name.
func CallAll(t *testing.T, target any, args map[string][]any, skip ...string) {
	t.Helper()

	ctx := t.Context()
	v := reflect.ValueOf(target)
	ctxType := reflect.TypeFor[context.Context]()
	for i := range v.NumMethod() {
		method := v.Type().Method(i)
		if slices.Contains(skip, method.Name) {
			continue
		}
		fn := v.Method(i)
		var in []reflect.Value
		if override, ok := args[method.Name]; ok {
			for _, a := range override {
				in = append(in, reflect.ValueOf(a))
			}
		} else {
			for j := range fn.Type().NumIn() {
				argType := fn.Type().In(j)
				switch {
				case fn.Type().IsVariadic() && j == fn.Type().NumIn()-1:
				case argType == ctxType:
					in = append(in, reflect.ValueOf(ctx))
				default:
					in = append(in, reflect.Zero(argType))
				}
			}
		}
		require.NotPanics(t, func() { fn.Call(in) }, "method %s", method.Name)
	}
}

func labelsAndBuckets(data metricdata.Aggregation) (labels []string, buckets []float64) {
	addKeys := func(set attribute.Set) {
		for _, kv := range set.ToSlice() {
			labels = append(labels, string(kv.Key))
		}
	}
	switch d := data.(type) {
	case metricdata.Sum[int64]:
		for _, p := range d.DataPoints {
			addKeys(p.Attributes)
		}
	case metricdata.Sum[float64]:
		for _, p := range d.DataPoints {
			addKeys(p.Attributes)
		}
	case metricdata.Gauge[int64]:
		for _, p := range d.DataPoints {
			addKeys(p.Attributes)
		}
	case metricdata.Gauge[float64]:
		for _, p := range d.DataPoints {
			addKeys(p.Attributes)
		}
	case metricdata.Histogram[int64]:
		for _, p := range d.DataPoints {
			addKeys(p.Attributes)
			buckets = p.Bounds
		}
	case metricdata.Histogram[float64]:
		for _, p := range d.DataPoints {
			addKeys(p.Attributes)
			buckets = p.Bounds
		}
	}
	return labels, buckets
}

// recordingMeter records the kind, unit and description of each synchronous instrument that is created.
type recordingMeter struct {
	metric.Meter
	created map[string]metricsgolden.Metric
}

func (r *recordingMeter) add(name, kind, unit, description string) {
	r.created[name] = metricsgolden.Metric{Name: name, Kind: kind, Unit: unit, Description: description}
}

func (r *recordingMeter) Int64Counter(name string, opts ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	c := metric.NewInt64CounterConfig(opts...)
	r.add(name, "Int64Counter", c.Unit(), c.Description())
	return r.Meter.Int64Counter(name, opts...)
}

func (r *recordingMeter) Int64UpDownCounter(name string, opts ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	c := metric.NewInt64UpDownCounterConfig(opts...)
	r.add(name, "Int64UpDownCounter", c.Unit(), c.Description())
	return r.Meter.Int64UpDownCounter(name, opts...)
}

func (r *recordingMeter) Int64Histogram(name string, opts ...metric.Int64HistogramOption) (metric.Int64Histogram, error) {
	c := metric.NewInt64HistogramConfig(opts...)
	r.add(name, "Int64Histogram", c.Unit(), c.Description())
	return r.Meter.Int64Histogram(name, opts...)
}

func (r *recordingMeter) Int64Gauge(name string, opts ...metric.Int64GaugeOption) (metric.Int64Gauge, error) {
	c := metric.NewInt64GaugeConfig(opts...)
	r.add(name, "Int64Gauge", c.Unit(), c.Description())
	return r.Meter.Int64Gauge(name, opts...)
}

func (r *recordingMeter) Float64Counter(name string, opts ...metric.Float64CounterOption) (metric.Float64Counter, error) {
	c := metric.NewFloat64CounterConfig(opts...)
	r.add(name, "Float64Counter", c.Unit(), c.Description())
	return r.Meter.Float64Counter(name, opts...)
}

func (r *recordingMeter) Float64UpDownCounter(name string, opts ...metric.Float64UpDownCounterOption) (metric.Float64UpDownCounter, error) {
	c := metric.NewFloat64UpDownCounterConfig(opts...)
	r.add(name, "Float64UpDownCounter", c.Unit(), c.Description())
	return r.Meter.Float64UpDownCounter(name, opts...)
}

func (r *recordingMeter) Float64Histogram(name string, opts ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	c := metric.NewFloat64HistogramConfig(opts...)
	r.add(name, "Float64Histogram", c.Unit(), c.Description())
	return r.Meter.Float64Histogram(name, opts...)
}

func (r *recordingMeter) Float64Gauge(name string, opts ...metric.Float64GaugeOption) (metric.Float64Gauge, error) {
	c := metric.NewFloat64GaugeConfig(opts...)
	r.add(name, "Float64Gauge", c.Unit(), c.Description())
	return r.Meter.Float64Gauge(name, opts...)
}
