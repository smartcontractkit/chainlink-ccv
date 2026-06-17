package load

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMessageDataSizeBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		profile     MessageProfileConfig
		defaultSize int
		want        int
	}{
		{
			name:        "no data",
			profile:     MessageProfileConfig{Name: "empty"},
			defaultSize: 1000,
			want:        0,
		},
		{
			name:        "has data uses default when size unset",
			profile:     MessageProfileConfig{Name: "data", HasData: true},
			defaultSize: 1000,
			want:        1000,
		},
		{
			name:        "has data uses explicit size",
			profile:     MessageProfileConfig{Name: "large", HasData: true, DataSizeBytes: 1500},
			defaultSize: 1000,
			want:        1500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, MessageDataSizeBytes(tt.profile, tt.defaultSize))
		})
	}
}
