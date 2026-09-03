// Package verifier holds the verifier's published API contracts and the generators that turn them
// into Go bindings and documentation. It carries no code of its own; the verifier's implementation
// lives under verifier/pkg.
//
// oapi-codegen is the installed binary rather than a go.mod tool dependency, matching indexer/,
// and just generate installs it first. Both directives are covered by the repo-hygiene job, which
// regenerates and fails if the tree changes, so neither the bindings nor the docs can drift from
// the spec.
package verifier

//go:generate oapi-codegen -config policy-codegen.yaml policy_hook_openapi_v1.yaml
//go:generate sh -c "./generate-docs.sh"
