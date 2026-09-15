// Package configdoc generates configuration/secrets documentation from Go
// structs, using the structs' Go doc comments as the single source of truth. It
// TOML-encodes a fully-populated instance and injects each field's doc comment
// above the emitted key.
//
// It is repo-agnostic and importable: a consuming repo builds a Generator (via
// NewGenerator, which auto-detects the enclosing module), declares its own
// []Target, and calls Write to generate or Check to verify freshness. The engine
// holds no repo-specific target list — see this repo's tools/configdoc/registry
// package for an example consumer.
//
// A config field whose *type* lives in a different module is documented from the DocComments
// method that module generated, so it needs no source tree here. A module that never generated
// has no comments to read, which trips the completeness gate.
package configdoc

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/mod/modfile"

	"github.com/smartcontractkit/chainlink-common/x/config/commentparsing"
)

// Generator renders documentation targets to commented TOML. ModuleRoot is the
// filesystem path of the module root; ModulePath is its import path. Prefer
// NewGenerator, which fills both by locating the enclosing go.mod.
type Generator struct {
	ModuleRoot string
	ModulePath string
}

// NewGenerator locates the Go module enclosing dir (walking up to the nearest
// go.mod), reads its module path, and returns a Generator rooted at the module
// directory. This lets the CLI and tests run from anywhere in the module without
// hardcoding the module path.
func NewGenerator(dir string) (*Generator, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for {
		if data, err := os.ReadFile(filepath.Join(abs, "go.mod")); err == nil { //nolint:gosec // G304: path is the ancestor-walked module root, not user input
			modPath, err := modulePath(data)
			if err != nil {
				return nil, fmt.Errorf("parsing %s/go.mod: %w", abs, err)
			}
			return &Generator{ModuleRoot: abs, ModulePath: modPath}, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return nil, fmt.Errorf("no go.mod found at or above %s", dir)
		}
		abs = parent
	}
}

// modulePath goes through the go tool's own parser because a directive may carry an inline
// comment, be quoted, or be separated by a tab.
func modulePath(gomod []byte) (string, error) {
	if path := modfile.ModulePath(gomod); path != "" {
		return path, nil
	}
	return "", errors.New("no module directive in go.mod")
}

// Stale describes a target whose committed doc differs from freshly generated
// output (or is missing). Want is the freshly generated content; Got is the
// committed content ("" when Missing).
type Stale struct {
	Target  Target
	Path    string
	Want    string
	Got     string
	Missing bool
}

// Write renders every target and writes it under outDir at the target's Out
// path, creating directories as needed. It returns the written file paths. A
// render or I/O error aborts and is returned along with the paths written so far.
func (g *Generator) Write(targets []Target, outDir string) ([]string, error) {
	rel, err := g.relative(outDir)
	if err != nil {
		return nil, err
	}

	// Run writes the DocComments methods for every package the walk reached alongside these docs,
	// out of the one discovery walk both need. That is what lets a downstream module document a
	// config field whose type is declared in this one.
	if err := commentparsing.Run(g.runArgs(targets), g.Files(targets, rel)); err != nil {
		return nil, err
	}

	written := make([]string, 0, len(targets))
	for _, t := range targets {
		written = append(written, filepath.Join(outDir, filepath.FromSlash(t.Out)))
	}
	return written, nil
}

// runArgs are what commentparsing needs beyond the targets themselves.
//
// Dir is the module root because every generated path is resolved against it, and a package's
// DocComments file belongs beside the structs it describes rather than under the docs directory.
func (g *Generator) runArgs(targets []Target) commentparsing.RunArgs {
	return commentparsing.RunArgs{
		Roots:       Roots(targets),
		Dir:         g.ModuleRoot,
		LocalPrefix: g.ModulePath,
		Tool:        g.ModulePath + "/tools/configdoc",
	}
}

// relative expresses outDir the way a generator's paths must be: against the module root the run
// is anchored to. A caller gives it relative to the working directory, which is the same thing
// only when that is the module root.
func (g *Generator) relative(outDir string) (string, error) {
	abs := outDir
	if !filepath.IsAbs(abs) {
		resolved, err := filepath.Abs(abs)
		if err != nil {
			return "", err
		}
		abs = resolved
	}
	return filepath.Rel(g.ModuleRoot, abs)
}

// files renders every target from one discovery walk, keyed by the path each is committed at.
//
// It goes through commentparsing.Files rather than Run so that checking whether the committed docs
// are up to date does not write the answer it is about to compare against.
func (g *Generator) files(targets []Target, outDir string) (map[string]string, error) {
	rel, err := g.relative(outDir)
	if err != nil {
		return nil, err
	}

	generated, err := commentparsing.Files(g.runArgs(targets), g.Files(targets, rel))
	if err != nil {
		return nil, fmt.Errorf("loading comments: %w", err)
	}

	// Keyed by the paths the caller built from outDir, not the module-root-relative ones the run
	// was anchored to, because those are what it compares against.
	files := make(map[string]string, len(targets))
	for _, t := range targets {
		out := filepath.FromSlash(t.Out)
		files[filepath.Join(outDir, out)] = generated[filepath.Join(rel, out)]
	}
	return files, nil
}

// Check renders every target and compares it against the committed file under
// outDir, returning the targets that are stale or missing (empty when all are
// fresh). A render error aborts and is returned. This is the engine behind both
// the CLI's -check mode and each repo's freshness test.
func (g *Generator) Check(targets []Target, outDir string) ([]Stale, error) {
	files, err := g.files(targets, outDir)
	if err != nil {
		return nil, err
	}

	// Only the targets are compared. The DocComments files written alongside them are guarded the
	// way any other generated Go is, by regenerating and diffing, and have no Target to name.
	var stale []Stale
	for _, t := range targets {
		path := filepath.Join(outDir, filepath.FromSlash(t.Out))
		want := files[path]
		got, err := os.ReadFile(path) //nolint:gosec // G304: path is built from the trusted target list + outDir, not user input
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				stale = append(stale, Stale{Target: t, Path: path, Want: want, Missing: true})
				continue
			}
			return nil, err
		}
		if string(got) != want {
			stale = append(stale, Stale{Target: t, Path: path, Want: want, Got: string(got)})
		}
	}
	return stale, nil
}

// Render produces the documented TOML for one target: it TOML-encodes the
// target's fully-populated instance (the encoder does all structure/value
// walking), loads the doc comments for the packages the instance's structs live
// in, and injects those comments into the encoded output.
func (g *Generator) Render(t Target) (string, error) {
	pkgs, err := commentparsing.Discover(g.ModuleRoot, t.New())
	if err != nil {
		return "", fmt.Errorf("%s: loading comments: %w", t.Name, err)
	}
	return g.render(t, commentsFrom(pkgs))
}

// render is Render with the comments already resolved, so several targets sharing a type resolve
// it once rather than each walking the tree again.
func (g *Generator) render(t Target, comments *CommentLookup) (string, error) {
	inst := t.New()
	if err := validateInitializedPointers(inst); err != nil {
		return "", fmt.Errorf("%s: %w", t.Name, err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(inst); err != nil {
		return "", fmt.Errorf("%s: encoding: %w", t.Name, err)
	}

	body, err := InjectComments(buf.String(), reflect.TypeOf(inst), comments)
	if err != nil {
		return "", fmt.Errorf("%s: %w", t.Name, err)
	}
	return g.header(t) + body, nil
}

// validateInitializedPointers ensures the example instance exposes every
// documented pointer-backed configuration section to the TOML encoder.
func validateInitializedPointers(inst any) error {
	var nilFields []string

	// walk recursively traverses the value tree of inst, recording the path of any
	// nil pointer fields. It follows pointers, structs, slices/arrays, and maps.
	var walk func(reflect.Value, string)
	walk = func(v reflect.Value, path string) {
		if !v.IsValid() {
			return
		}

		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() {
				nilFields = append(nilFields, path)
				return
			}
			walk(v.Elem(), path)
		case reflect.Struct:
			for i := range v.NumField() {
				f := v.Type().Field(i)
				if !f.IsExported() {
					continue
				}
				fieldPath := f.Name
				if path != "" {
					fieldPath = path + "." + fieldPath
				}
				if f.Anonymous {
					// Polymorphic config types use nil embedded pointers and custom
					// unmarshalling, so they are not TOML sections to document here.
					if f.Type.Kind() == reflect.Pointer {
						continue
					}
					walk(v.Field(i), fieldPath)
					continue
				}
				if key, ok := tomlKey(f); !ok || key == "" {
					continue
				}
				walk(v.Field(i), fieldPath)
			}
		case reflect.Slice, reflect.Array:
			for i := range v.Len() {
				walk(v.Index(i), path)
			}
		case reflect.Map:
			iter := v.MapRange()
			for iter.Next() {
				walk(iter.Value(), path)
			}
		}
	}

	walk(reflect.ValueOf(inst), "")
	if len(nilFields) == 0 {
		return nil
	}
	return fmt.Errorf(
		"uninitialized pointer fields: %s; all config struct pointer fields must be initialized for documentation purposes",
		strings.Join(nilFields, ", "),
	)
}

func (g *Generator) header(t Target) string {
	kind := "configuration"
	if t.Kind == KindSecrets {
		kind = "secrets"
	}
	return fmt.Sprintf(
		"# Code generated by tools/configdoc. DO NOT EDIT.\n"+
			"# %s %s reference. Values shown are defaults or illustrative examples.\n\n",
		titleCase(t.Name), kind,
	)
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
