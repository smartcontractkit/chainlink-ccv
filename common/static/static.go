// Package static holds the build identity injected into service binaries at link time.
package static

// Unset marks a build without injected identity: not a release tag, or no git metadata.
const Unset = "unset"

var (
	// Version is the release tag this binary was built from, or Unset.
	Version = Unset
	// Sha is the full commit this binary was built from, or Unset.
	Sha = Unset
)
