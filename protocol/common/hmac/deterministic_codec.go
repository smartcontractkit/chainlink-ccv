package hmac

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"
)

// Must be a CodecV2: wrappers like otel pdata's codec look up the "proto" CodecV2 as their fallback,
// and a V1 registration makes that lookup nil, panicking every non-OTLP gRPC call.
func init() {
	encoding.RegisterCodecV2(DeterministicCodec{})
}

// DeterministicCodec replaces the global "proto" gRPC codec so wire bytes match what was HMAC-signed.
type DeterministicCodec struct{}

func (DeterministicCodec) Marshal(v any) (mem.BufferSlice, error) {
	msg, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("DeterministicCodec: not a proto.Message: %T", v)
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return mem.BufferSlice{mem.SliceBuffer(b)}, nil
}

func (DeterministicCodec) Unmarshal(data mem.BufferSlice, v any) error {
	msg, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("DeterministicCodec: not a proto.Message: %T", v)
	}
	buf := data.MaterializeToBuffer(mem.DefaultBufferPool())
	defer buf.Free()
	return proto.Unmarshal(buf.ReadOnlyData(), msg)
}

func (DeterministicCodec) Name() string {
	return "proto"
}
