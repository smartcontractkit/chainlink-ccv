package hmac

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/proto"
)

func init() {
	encoding.RegisterCodec(DeterministicCodec{})
}

// DeterministicCodec is a gRPC codec that uses deterministic protobuf marshaling.
// This ensures the bytes sent over the wire match what was used for HMAC signing,
// preventing transient signature validation failures caused by non-deterministic
// protobuf serialization.
//
// The codec is registered globally via init() and replaces the default "proto" codec.
// All gRPC connections in the process will use deterministic marshaling.
type DeterministicCodec struct{}

func (DeterministicCodec) Marshal(v any) ([]byte, error) {
	msg, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("DeterministicCodec: not a proto.Message: %T", v)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(msg)
}

func (DeterministicCodec) Unmarshal(data []byte, v any) error {
	msg, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("DeterministicCodec: not a proto.Message: %T", v)
	}
	return proto.Unmarshal(data, msg)
}

func (DeterministicCodec) Name() string {
	return "proto"
}
