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
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/mod/modfile"

	"github.com/smartcontractkit/chainlink-common/x/config/commentparsing"
	"github.com/smartcontractkit/chainlink-common/x/config/markup/tomlmarkup"
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

// Stale describes a generated file whose committed copy differs from fresh output (or is
// missing). Want is the fresh content; Got is the committed content ("" when Missing).
// A DocComments file has no target, so Target carries only its path relative to the module root.
type Stale struct {
	Target  Target
	Path    string
	Want    string
	Got     string
	Missing bool
}

// Write renders every target and writes it under outDir at the target's Out
// path, creating directories as needed. It returns the written file paths.
// outDir must resolve inside the module root, which is where the run is anchored.
//
// Pass the module's whole target list, as Main does. A run rewrites the DocComments file of every
// package its walk reaches and drops the ones this tool wrote that it did not produce, so a subset
// takes the omitted targets' methods with it.
//
// An error returns no paths. The write is one commentparsing run over the docs and the
// DocComments files together, which reports whether it completed rather than which files it got
// to, so there is no partial list to hand back; a failed run leaves the tree to be repaired by
// rerunning, not by reading a prefix of what it managed.
func (g *Generator) Write(targets []Target, outDir string) ([]string, error) {
	rel, err := g.relative(outDir)
	if err != nil {
		return nil, err
	}

	// One walk feeds both these docs and the DocComments methods Run writes beside them, which is
	// what lets a downstream module document a field whose type is declared in this one.
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
		Markup:      tomlmarkup.New(),
		Dir:         g.ModuleRoot,
		LocalPrefix: g.ModulePath,
		Tool:        g.ModulePath + "/tools/configdoc",
	}
}

// relative expresses outDir the way a generator's paths must be: against the module root the run
// is anchored to. A caller gives it relative to the working directory, which is the same thing
// only when that is the module root.
//
// A directory outside the module is refused here rather than deeper in. The run is anchored at
// the module root so each package's DocComments file lands beside the structs it describes, and
// it will not write above that anchor; the error it raises names a path relative to a directory
// the caller never supplied, so this one names the directory the caller did.
func (g *Generator) relative(outDir string) (string, error) {
	abs := outDir
	if !filepath.IsAbs(abs) {
		resolved, err := filepath.Abs(abs)
		if err != nil {
			return "", err
		}
		abs = resolved
	}
	rel, err := filepath.Rel(g.ModuleRoot, abs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf(
			"output directory %s is outside module root %s: docs are written within the module being documented",
			outDir, g.ModuleRoot,
		)
	}
	return rel, nil
}

// files renders every target and DocComments file from one discovery walk, keyed by the path each
// is committed at.
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

	// A target's doc is keyed by the path the caller built from outDir; everything else by its
	// path under the module root.
	files := make(map[string]string, len(generated))
	for path, content := range generated {
		files[filepath.Join(g.ModuleRoot, path)] = content
	}
	for _, t := range targets {
		out := filepath.FromSlash(t.Out)
		root := filepath.Join(g.ModuleRoot, rel, out)
		content := files[root]
		delete(files, root)
		files[filepath.Join(outDir, out)] = content
	}
	return files, nil
}

// Check renders every target and DocComments file and compares each against its committed copy,
// returning the stale or missing ones (empty when all are fresh). outDir is restricted as Write's
// is. Stale targets come first, in target order, then DocComments files sorted by path.
func (g *Generator) Check(targets []Target, outDir string) ([]Stale, error) {
	files, err := g.files(targets, outDir)
	if err != nil {
		return nil, err
	}

	// A DocComments file Run would delete is not caught here; the regenerate-and-diff CI job does.
	var stale []Stale
	for _, t := range targets {
		path := filepath.Join(outDir, filepath.FromSlash(t.Out))
		s, err := compare(path, files[path])
		if err != nil {
			return nil, err
		}
		if s != nil {
			s.Target = t
			stale = append(stale, *s)
		}
		delete(files, path)
	}
	for _, path := range slices.Sorted(maps.Keys(files)) {
		s, err := compare(path, files[path])
		if err != nil {
			return nil, err
		}
		if s != nil {
			rel, err := filepath.Rel(g.ModuleRoot, path)
			if err != nil {
				return nil, err
			}
			s.Target = Target{Out: filepath.ToSlash(rel)}
			stale = append(stale, *s)
		}
	}
	return stale, nil
}

// compare returns nil when the file at path already holds want.
func compare(path, want string) (*Stale, error) {
	got, err := os.ReadFile(path) //nolint:gosec // G304: path comes from the generated file set, not user input
	if errors.Is(err, fs.ErrNotExist) {
		return &Stale{Path: path, Want: want, Missing: true}, nil
	}
	if err != nil {
		return nil, err
	}
	if string(got) == want {
		return nil, nil
	}
	return &Stale{Path: path, Want: want, Got: string(got)}, nil
}

// Render produces the documented TOML for one target: it TOML-encodes the
// target's fully-populated instance (the encoder does all structure/value
// walking), loads the doc comments for the packages the instance's structs live
// in, and injects those comments into the encoded output.
func (g *Generator) Render(t Target) (string, error) {
	files, err := g.files([]Target{t}, g.ModuleRoot)
	if err != nil {
		return "", err
	}
	return files[filepath.Join(g.ModuleRoot, filepath.FromSlash(t.Out))], nil
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
