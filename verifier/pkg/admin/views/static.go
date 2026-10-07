package views

import "embed"

// The .templ sources compile to the committed *_templ.go files. Regenerating runs
// through `go generate` (the repo hygiene check), so a stale *_templ.go fails CI.
//
//go:generate templ generate

// StaticFS carries vendored browser assets (htmx, stylesheet, icon). Vendored,
// not CDN-loaded, so the console works on isolated networks.
//
//go:embed static
var StaticFS embed.FS
