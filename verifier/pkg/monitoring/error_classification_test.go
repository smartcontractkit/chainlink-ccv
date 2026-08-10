package monitoring

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		errorClass string
		err        error
		want       string
	}{
		{"configured source chain", errors.New("message source chain selector 1 is not configured"), "source_chain_not_configured"},
		{"not ready attestation", errors.New("attestation not ready for message ID"), "attestation_not_ready"},
		{"aggregator unavailable", errors.New("rpc error: code = Unavailable"), "aggregator_unavailable"},
		{"unknown", errors.New("unexpected failure"), "unknown"},
		{"nil", nil, "unknown"},
	}

	for _, test := range tests {
		t.Run(test.errorClass, func(t *testing.T) {
			assert.Equal(t, test.want, ClassifyError(test.err))
		})
	}
}
