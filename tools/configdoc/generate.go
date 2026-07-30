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
// Limitation: doc comments are only harvested for packages inside the Generator's
// module. A config field whose *type* lives in a different module is still
// emitted but gets no comment, which trips the completeness gate — so keep a
// repo's config structs (and their nested types) within that repo's module.
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

// modulePath extracts the module import path from go.mod contents.
func modulePath(gomod []byte) (string, error) {
	for line := range strings.SplitSeq(string(gomod), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest), nil
		}
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
	var written []string
	for _, t := range targets {
		content, err := g.Render(t)
		if err != nil {
			return written, err
		}
		path := filepath.Join(outDir, filepath.FromSlash(t.Out))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return written, err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // G306: generated docs are not secret
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// Check renders every target and compares it against the committed file under
// outDir, returning the targets that are stale or missing (empty when all are
// fresh). A render error aborts and is returned. This is the engine behind both
// the CLI's -check mode and each repo's freshness test.
func (g *Generator) Check(targets []Target, outDir string) ([]Stale, error) {
	var stale []Stale
	for _, t := range targets {
		want, err := g.Render(t)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(outDir, filepath.FromSlash(t.Out))
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
	inst := t.New()
	if err := validateInitializedPointers(inst); err != nil {
		return "", fmt.Errorf("%s: %w", t.Name, err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(inst); err != nil {
		return "", fmt.Errorf("%s: encoding: %w", t.Name, err)
	}

	comments, err := LoadComments(g.packageDirs(inst))
	if err != nil {
		return "", fmt.Errorf("%s: loading comments: %w", t.Name, err)
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

// packageDirs maps each package contributing a field on inst to its source
// directory, so LoadComments indexes exactly the needed packages.
func (g *Generator) packageDirs(inst any) map[string]string {
	dirs := make(map[string]string)
	for pkg := range collectPackages(reflect.TypeOf(inst)) {
		rel := strings.TrimPrefix(strings.TrimPrefix(pkg, g.ModulePath), "/")
		dirs[pkg] = filepath.Join(g.ModuleRoot, filepath.FromSlash(rel))
	}
	return dirs
}

// collectPackages returns the set of package import paths of every struct type
// reachable through the fields of t (following embeds, nested structs, and
// struct-valued maps/slices).
func collectPackages(t reflect.Type) map[string]bool {
	out := make(map[string]bool)
	visited := make(map[reflect.Type]bool)
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		t = deref(t)
		if t.Kind() != reflect.Struct || visited[t] {
			return
		}
		visited[t] = true
		if t.PkgPath() != "" {
			out[t.PkgPath()] = true
		}
		for _, f := range reflect.VisibleFields(t) {
			if !f.IsExported() {
				continue
			}
			ft := deref(f.Type)
			switch ft.Kind() {
			case reflect.Struct:
				walk(ft)
			case reflect.Slice, reflect.Array, reflect.Map:
				if ft.Elem().Kind() == reflect.Struct {
					walk(ft.Elem())
				}
			}
		}
	}
	walk(t)
	return out
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
