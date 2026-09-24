package views

import "embed"

// StaticFS carries vendored browser assets (htmx, stylesheet, icon). Vendored,
// not CDN-loaded, so the console works on isolated networks.
//
//go:embed static
var StaticFS embed.FS
