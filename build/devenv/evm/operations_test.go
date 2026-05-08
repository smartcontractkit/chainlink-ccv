package evm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-ccv/build/devenv/cciptestinterfaces"
	"github.com/smartcontractkit/chainlink-ccv/protocol"
)

// decodeNewV3ExtraArgs parses GenericExtraArgsV3 bytes produced by NewV3ExtraArgs into MessageOptions.
// Fields not present on the wire (e.g. OutOfOrderExecution) are left at zero values.
func decodeNewV3ExtraArgs(encoded []byte) (cciptestinterfaces.MessageOptions, error) {
	var out cciptestinterfaces.MessageOptions
	r := bytes.NewReader(encoded)

	var tag [4]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return out, fmt.Errorf("read tag: %w", err)
	}
	if !bytes.Equal(tag[:], GenericExtraArgsV3Tag) {
		return out, fmt.Errorf("unexpected tag %x want %x", tag[:], GenericExtraArgsV3Tag)
	}

	if err := binary.Read(r, binary.BigEndian, &out.ExecutionGasLimit); err != nil {
		return out, fmt.Errorf("gasLimit: %w", err)
	}
	var fin uint32
	if err := binary.Read(r, binary.BigEndian, &fin); err != nil {
		return out, fmt.Errorf("finality: %w", err)
	}
	out.FinalityConfig = protocol.Finality(fin)

	ccvCount, err := r.ReadByte()
	if err != nil {
		return out, fmt.Errorf("ccvsLength: %w", err)
	}
	out.CCVs = make([]protocol.CCV, ccvCount)
	for i := range out.CCVs {
		addrLen, err := r.ReadByte()
		if err != nil {
			return out, fmt.Errorf("ccv[%d] addr len: %w", i, err)
		}
		if addrLen != 0 && addrLen != EVMAddressLength {
			return out, fmt.Errorf("ccv[%d] invalid addr len %d", i, addrLen)
		}
		addrBytes := make([]byte, addrLen)
		if addrLen > 0 {
			if _, err := io.ReadFull(r, addrBytes); err != nil {
				return out, fmt.Errorf("ccv[%d] addr: %w", i, err)
			}
		}
		args, err := readUint16LengthPrefixedBytes(r, "ccvArgs")
		if err != nil {
			return out, fmt.Errorf("ccv[%d] %w", i, err)
		}
		out.CCVs[i] = protocol.CCV{
			CCVAddress: common.BytesToAddress(addrBytes).Bytes(),
			Args:       args,
		}
	}

	execLen, err := r.ReadByte()
	if err != nil {
		return out, fmt.Errorf("executor len: %w", err)
	}
	if execLen != 0 && execLen != EVMAddressLength {
		return out, fmt.Errorf("invalid executor len %d", execLen)
	}
	execBytes := make([]byte, execLen)
	if execLen > 0 {
		if _, err := io.ReadFull(r, execBytes); err != nil {
			return out, fmt.Errorf("executor: %w", err)
		}
	}
	execAddr := common.BytesToAddress(execBytes)
	out.Executor = execAddr.Bytes()

	out.ExecutorArgs, err = readUint16LengthPrefixedBytes(r, "executorArgs")
	if err != nil {
		return out, err
	}

	trLen, err := r.ReadByte()
	if err != nil {
		return out, fmt.Errorf("tokenReceiver len: %w", err)
	}
	if int(trLen) > MaxTokenReceiverLength {
		return out, fmt.Errorf("tokenReceiver len %d exceeds max %d", trLen, MaxTokenReceiverLength)
	}
	out.TokenReceiver = make([]byte, trLen)
	if trLen > 0 {
		if _, err := io.ReadFull(r, out.TokenReceiver); err != nil {
			return out, fmt.Errorf("tokenReceiver: %w", err)
		}
	}

	out.TokenArgs, err = readUint16LengthPrefixedBytes(r, "tokenArgs")
	if err != nil {
		return out, err
	}

	if r.Len() != 0 {
		return out, fmt.Errorf("trailing %d bytes after tokenArgs", r.Len())
	}

	return out, nil
}

func readUint16LengthPrefixedBytes(r *bytes.Reader, field string) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, fmt.Errorf("%s length: %w", field, err)
	}
	if r.Len() < int(n) {
		return nil, fmt.Errorf("%s: want %d payload bytes, %d available", field, n, r.Len())
	}
	out := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, out); err != nil {
			return nil, fmt.Errorf("%s payload: %w", field, err)
		}
	}
	return out, nil
}

func zeroExecutorMessageOptions() cciptestinterfaces.MessageOptions {
	return cciptestinterfaces.MessageOptions{
		CCVs:          []protocol.CCV{},
		Executor:      protocol.UnknownAddress(common.Address{}.Bytes()),
		ExecutorArgs:  []byte{},
		TokenReceiver: []byte{},
		TokenArgs:     []byte{},
	}
}

func TestNewV3ExtraArgs_roundTrip(t *testing.T) {
	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	t.Run("minimal_empty_blobs", func(t *testing.T) {
		finality := protocol.Finality(7)
		gas := uint32(500_000)
		execAddr := (common.Address{}).Hex()

		encoded, err := NewV3ExtraArgs(finality, gas, execAddr, nil, nil, nil, nil)
		require.NoError(t, err)

		got, err := decodeNewV3ExtraArgs(encoded)
		require.NoError(t, err)
		want := zeroExecutorMessageOptions()
		want.ExecutionGasLimit = gas
		want.FinalityConfig = finality
		require.Equal(t, want, got)
	})

	t.Run("exec_and_token_args_nonempty", func(t *testing.T) {
		execArgs := []byte{1, 2, 3, 4}
		tokenArgs := []byte{0xab, 0xcd}
		encoded, err := NewV3ExtraArgs(0, 100, (common.Address{}).Hex(), execArgs, nil, tokenArgs, nil)
		require.NoError(t, err)
		got, err := decodeNewV3ExtraArgs(encoded)
		require.NoError(t, err)
		want := zeroExecutorMessageOptions()
		want.ExecutionGasLimit = 100
		want.ExecutorArgs = execArgs
		want.TokenArgs = tokenArgs
		require.Equal(t, want, got)
	})

	t.Run("token_receiver_20_bytes", func(t *testing.T) {
		rcv := addr1.Bytes()
		encoded, err := NewV3ExtraArgs(0, 0, (common.Address{}).Hex(), nil, rcv, nil, nil)
		require.NoError(t, err)
		got, err := decodeNewV3ExtraArgs(encoded)
		require.NoError(t, err)
		want := zeroExecutorMessageOptions()
		want.TokenReceiver = rcv
		require.Equal(t, want, got)
	})

	t.Run("token_receiver_32_bytes_solana_shaped", func(t *testing.T) {
		rcv := bytes.Repeat([]byte{0x42}, 32)
		encoded, err := NewV3ExtraArgs(0, 0, (common.Address{}).Hex(), nil, rcv, nil, nil)
		require.NoError(t, err)
		got, err := decodeNewV3ExtraArgs(encoded)
		require.NoError(t, err)
		want := zeroExecutorMessageOptions()
		want.TokenReceiver = rcv
		require.Equal(t, want, got)
	})

	t.Run("token_receiver_max_length_255", func(t *testing.T) {
		rcv := bytes.Repeat([]byte{0xfe}, MaxTokenReceiverLength)
		encoded, err := NewV3ExtraArgs(0, 0, (common.Address{}).Hex(), nil, rcv, nil, nil)
		require.NoError(t, err)
		got, err := decodeNewV3ExtraArgs(encoded)
		require.NoError(t, err)
		want := zeroExecutorMessageOptions()
		want.TokenReceiver = rcv
		require.Equal(t, want, got)
	})

	t.Run("executor_and_ccvs", func(t *testing.T) {
		ccvs := []protocol.CCV{
			{CCVAddress: protocol.UnknownAddress(addr1.Bytes()), Args: []byte{0x01}},
			{CCVAddress: protocol.UnknownAddress(addr2.Bytes()), Args: []byte{0x02, 0x03}},
		}
		fin := protocol.NewFinality().WithBlockDepth(3)
		encoded, err := NewV3ExtraArgs(
			fin,
			999_999,
			addr1.Hex(),
			[]byte("exec-payload"),
			[]byte{0xaa},
			[]byte("tok"),
			ccvs,
		)
		require.NoError(t, err)
		got, err := decodeNewV3ExtraArgs(encoded)
		require.NoError(t, err)
		want := cciptestinterfaces.MessageOptions{
			ExecutionGasLimit: 999_999,
			FinalityConfig:    fin,
			CCVs:              ccvs,
			Executor:          protocol.UnknownAddress(addr1.Bytes()),
			ExecutorArgs:      []byte("exec-payload"),
			TokenReceiver:     []byte{0xaa},
			TokenArgs:         []byte("tok"),
		}
		require.Equal(t, want, got)
	})
}

func TestNewV3ExtraArgs_tokenReceiverTooLong(t *testing.T) {
	tooLong := make([]byte, MaxTokenReceiverLength+1)
	_, err := NewV3ExtraArgs(0, 0, (common.Address{}).Hex(), nil, tooLong, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token receiver too long")
}
