// Package configvalidate provides strict TOML decoding helpers used to validate
// that a deploy config decodes cleanly into an app's config struct before the
// config reaches a running service.
//
// "Strict" means two things beyond a normal decode:
//   - a decode error (e.g. a type mismatch such as a bare integer where a quoted
//     duration string is required) is surfaced, and
//   - any key present in the TOML but absent from the target struct is reported
//     as "undecoded". The standard service loaders are non-strict and silently
//     drop such keys, so a renamed or removed config key falls back to a code
//     default with no error. Reporting these keys catches config drift before it
//     reaches production.
package configvalidate

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// DecodeFileStrict decodes the TOML file at path into target and returns the
// sorted list of keys that were present in the file but did not map to any field
// of target. File handling stays in the toml library (avoiding a caller-side
// os.ReadFile of a variable path).
//
// A non-empty undecoded list indicates config drift, not a decode failure: err
// is only non-nil when the file is missing, the TOML is malformed, or a value
// fails to decode (for example a custom UnmarshalTOML implementation rejecting
// it).
func DecodeFileStrict(path string, target any) (undecoded []string, err error) {
	md, err := toml.DecodeFile(path, target)
	if err != nil {
		return nil, err
	}
	return collectUndecoded(md), nil
}

func collectUndecoded(md toml.MetaData) []string {
	keys := md.Undecoded()
	undecoded := make([]string, 0, len(keys))
	for _, k := range keys {
		undecoded = append(undecoded, k.String())
	}
	slices.Sort(undecoded)
	return undecoded
}

// Result is the outcome of strictly decoding one named TOML document.
type Result struct {
	// Name labels the document in error output (e.g. "aggregator.toml").
	Name string
	// Undecoded lists keys present in the document but absent from the struct.
	Undecoded []string
	// Err is a decode or parse failure, if any.
	Err error
}

// Report combines results into a single error describing every decode failure
// and every undecoded key, or returns nil when all documents decoded cleanly
// with no drift.
func Report(results ...Result) error {
	var b strings.Builder
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(&b, "%s: decode error: %v\n", r.Name, r.Err)
		case len(r.Undecoded) > 0:
			fmt.Fprintf(&b, "%s: unknown keys not present in the config struct (drift):\n", r.Name)
			for _, k := range r.Undecoded {
				fmt.Fprintf(&b, "  - %s\n", k)
			}
		}
	}
	if b.Len() == 0 {
		return nil
	}
	return errors.New(strings.TrimRight(b.String(), "\n"))
}
