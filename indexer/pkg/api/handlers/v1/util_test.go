package v1

import (
	"testing"
	"time"
)

func TestParseTime(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{"empty", "", 0, false},
		{"rfc3339", "2020-01-02T15:04:05Z", time.Date(2020, 1, 2, 15, 4, 5, 0, time.UTC).UnixMilli(), false},
		{"rfc3339_fraction", "2020-01-02T15:04:05.123Z", time.Date(2020, 1, 2, 15, 4, 5, 123000000, time.UTC).UnixMilli(), false},
		{"rfc3339_offset", "2020-01-02T15:04:05+02:00", func() int64 { t, _ := time.Parse(time.RFC3339, "2020-01-02T15:04:05+02:00"); return t.UnixMilli() }(), false},
		{"epoch", "1600000000123", 1600000000123, false},
		{"invalid", "notatime", 0, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseTime(c.input)
			if (err != nil) != c.wantErr {
				t.Fatalf("parseTime(%q) err = %v, wantErr=%v", c.input, err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("parseTime(%q) = %v, want %v", c.input, got, c.want)
			}
		})
	}
}
