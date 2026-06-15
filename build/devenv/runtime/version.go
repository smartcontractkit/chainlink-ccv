package devenvruntime

import "fmt"

// CheckConfigVersion reports whether a decoded component config version (got) is
// compatible with the version this build of the component supports (want).
//
// Each component declares its own exported Version constant and calls this after
// decoding its config. The policy here is exact match: a component supports
// exactly one config version at a time. A component that wants different
// behavior (e.g. accepting a range of backwards-compatible versions) is free to
// implement its own check instead of calling this helper — version compatibility
// is the component's decision.
func CheckConfigVersion(got, want int) error {
	if got != want {
		return fmt.Errorf("unsupported config version %d; supported version is %d", got, want)
	}
	return nil
}
