package configvalidate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sample struct {
	Name    string  `toml:"name"`
	Count   int     `toml:"count"`
	Nested  nested  `toml:"nested"`
	Pointer *nested `toml:"pointer"`
}

type nested struct {
	Enabled bool `toml:"enabled"`
}

func writeTOML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestDecodeFileStrict(t *testing.T) {
	t.Run("clean config has no undecoded keys", func(t *testing.T) {
		var s sample
		undecoded, err := DecodeFileStrict(writeTOML(t, `
name = "ok"
count = 3
[nested]
enabled = true
`), &s)
		require.NoError(t, err)
		assert.Empty(t, undecoded)
		assert.Equal(t, "ok", s.Name)
		assert.Equal(t, 3, s.Count)
		assert.True(t, s.Nested.Enabled)
	})

	t.Run("unknown keys are reported, sorted, dotted", func(t *testing.T) {
		var s sample
		undecoded, err := DecodeFileStrict(writeTOML(t, `
name = "ok"
zzz = "drifted"
aaa = "also drifted"
[nested]
enabled = true
bogus = 1
`), &s)
		require.NoError(t, err)
		assert.Equal(t, []string{"aaa", "nested.bogus", "zzz"}, undecoded)
	})

	t.Run("type mismatch surfaces as a decode error", func(t *testing.T) {
		var s sample
		// count is an int; a quoted string is not assignable.
		_, err := DecodeFileStrict(writeTOML(t, `count = "not-an-int"`), &s)
		require.Error(t, err)
	})

	t.Run("malformed toml surfaces as a decode error", func(t *testing.T) {
		var s sample
		_, err := DecodeFileStrict(writeTOML(t, `name = `), &s)
		require.Error(t, err)
	})

	t.Run("missing file surfaces as an error", func(t *testing.T) {
		var s sample
		_, err := DecodeFileStrict(filepath.Join(t.TempDir(), "nope.toml"), &s)
		require.Error(t, err)
	})
}

func TestReport(t *testing.T) {
	t.Run("all clean returns nil", func(t *testing.T) {
		err := Report(
			Result{Name: "a.toml"},
			Result{Name: "b.toml", Undecoded: nil},
		)
		assert.NoError(t, err)
	})

	t.Run("aggregates decode errors and drift across documents", func(t *testing.T) {
		err := Report(
			Result{Name: "main.toml", Undecoded: []string{"foo", "bar.baz"}},
			Result{Name: "generated.toml", Err: assertErr("boom")},
		)
		require.Error(t, err)
		msg := err.Error()
		assert.Contains(t, msg, "main.toml: unknown keys")
		assert.Contains(t, msg, "  - foo")
		assert.Contains(t, msg, "  - bar.baz")
		assert.Contains(t, msg, "generated.toml: boom")
	})
}

type assertErr string

func (e assertErr) Error() string { return string(e) }
