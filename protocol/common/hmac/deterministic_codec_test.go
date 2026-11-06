package hmac

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestDeterministicCodec_IsRegistered(t *testing.T) {
	codec := encoding.GetCodecV2("proto")
	require.NotNil(t, codec, "proto CodecV2 should be registered")

	_, ok := codec.(DeterministicCodec)
	require.True(t, ok, "registered codec should be DeterministicCodec")
}

func TestDeterministicCodec_Name(t *testing.T) {
	codec := DeterministicCodec{}
	require.Equal(t, "proto", codec.Name())
}

func TestDeterministicCodec_MarshalUnmarshal(t *testing.T) {
	codec := DeterministicCodec{}
	original := wrapperspb.String("test value")

	data, err := codec.Marshal(original)
	require.NoError(t, err)
	require.NotZero(t, data.Len())

	result := &wrapperspb.StringValue{}
	err = codec.Unmarshal(data, result)
	require.NoError(t, err)
	require.Equal(t, original.GetValue(), result.GetValue())
}

func TestDeterministicCodec_MarshalProducesDeterministicOutput(t *testing.T) {
	codec := DeterministicCodec{}
	msg := wrapperspb.String("deterministic test")

	data1, err := codec.Marshal(msg)
	require.NoError(t, err)

	data2, err := codec.Marshal(msg)
	require.NoError(t, err)

	require.Equal(t, data1.Materialize(), data2.Materialize(), "multiple marshals should produce identical bytes")
}

func TestDeterministicCodec_MarshalNonProtoMessageReturnsError(t *testing.T) {
	codec := DeterministicCodec{}

	_, err := codec.Marshal("not a proto message")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a proto.Message")
}

func TestDeterministicCodec_UnmarshalNonProtoMessageReturnsError(t *testing.T) {
	codec := DeterministicCodec{}

	var notProto string
	err := codec.Unmarshal(mem.BufferSlice{}, &notProto)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a proto.Message")
}
