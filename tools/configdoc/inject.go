package configdoc

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// InjectComments annotates encoder-produced TOML with the Go doc comments of the
// struct it was encoded from. For each key and table it resolves the originating
// field live from rootType (via CommentLookup) and prepends the comment as `#`
// lines at the line's indentation. Top-level fields are separated by a blank line
// for readability.
//
// This is the only bespoke walking the generator does: the TOML encoder already
// produced structure and values; here we only map emitted keys back to fields to
// attach comments. Returns an error if a documented field has no comment.
func InjectComments(tomlText string, rootType reflect.Type, comments *CommentLookup) (string, error) {
	root := deref(rootType)
	var b strings.Builder
	var errs []error

	curElem := root       // struct type whose fields the current (non-table) key lines belong to
	topLevelSeen := false // to separate top-level fields with a blank line

	for line := range strings.SplitSeq(tomlText, "\n") {
		trimmed := strings.TrimSpace(line)
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]

		switch {
		case trimmed == "":
			writeLine(&b, line)

		case strings.HasPrefix(trimmed, "["): // [table] or [[array-of-tables]]
			path := strings.Trim(strings.Trim(trimmed, "[]"), " ")
			segs := splitPath(path)
			comment, lastStatic, elem, err := resolveTable(root, segs, comments)
			if err != nil {
				errs = append(errs, err)
				writeLine(&b, line)
				continue
			}
			if lastStatic {
				writeComment(&b, indent, segs[len(segs)-1], comment)
			}
			writeLine(&b, line)
			curElem = elem

		default: // key = value
			key, _, _ := strings.Cut(trimmed, "=")
			key = strings.TrimSpace(key)
			if indent == "" { // top-level field: blank-line separator between fields
				if topLevelSeen {
					writeLine(&b, "")
				}
				topLevelSeen = true
			}
			if f, declType, ok := fieldByTOMLKey(curElem, key); ok {
				c := comments.Field(declType.PkgPath(), declType.Name(), f.Name)
				if c == "" {
					errs = append(errs, fmt.Errorf("%s.%s: missing doc comment", declType.Name(), f.Name))
				}
				writeComment(&b, indent, key, c)
			}
			writeLine(&b, line)
		}
	}
	return b.String(), errors.Join(errs...)
}

// resolveTable resolves an encoded table path against the root struct type. It
// returns the doc comment of the deepest static field in the path, whether that
// last segment was a static field (vs a dynamic map key), and the struct type
// whose fields the table's keys belong to.
//
// Field segments and map-key segments differ: a struct field that is a slice of
// structs (`[[clients]]`) or a nested array (`[[clients.apiKeyPair]]`) contributes
// only its field name to the path — TOML arrays-of-tables carry no index segment
// — whereas a map (`[committee.quorumConfigs.1]`) contributes a dynamic key
// segment. So after matching a field or consuming a map key we descend through
// pointers and slice/array elements (but not maps) to the container the next
// segment indexes.
func resolveTable(root reflect.Type, segs []string, comments *CommentLookup) (comment string, lastStatic bool, elem reflect.Type, err error) {
	ctx := descend(root)
	for _, seg := range segs {
		switch ctx.Kind() {
		case reflect.Struct:
			f, declType, ok := fieldByTOMLKey(ctx, seg)
			if !ok {
				return "", false, nil, fmt.Errorf("unknown TOML key %q in %s", seg, ctx.Name())
			}
			comment = comments.Field(declType.PkgPath(), declType.Name(), f.Name)
			lastStatic = true
			ctx = descend(f.Type)
		case reflect.Map:
			lastStatic = false // dynamic map key
			ctx = descend(ctx.Elem())
		default:
			return "", false, nil, fmt.Errorf("cannot descend into %s at %q", ctx.Kind(), seg)
		}
	}
	return comment, lastStatic, ctx, nil
}

// descend unwraps pointers and slice/array element types to reach the struct or
// map a path segment indexes into. It deliberately does not unwrap maps: a map
// contributes a dynamic key segment that resolveTable consumes explicitly.
func descend(t reflect.Type) reflect.Type {
	for {
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			t = t.Elem()
		default:
			return t
		}
	}
}

// fieldByTOMLKey finds the field of struct type t (including promoted fields from
// embedded structs) whose TOML key matches key, returning the field and its
// declaring type (which, for a promoted field, is the embedded struct).
//
// Embedded struct fields are matched by their own TOML key only when they carry a
// tag: the encoder renders a tagged embed as its own table ([kms.aws]), while an
// untagged embed is flattened into the parent and its promoted fields — which also
// appear in VisibleFields — are matched individually.
func fieldByTOMLKey(t reflect.Type, key string) (reflect.StructField, reflect.Type, bool) {
	t = deref(t)
	if t.Kind() != reflect.Struct {
		return reflect.StructField{}, nil, false
	}
	for _, f := range reflect.VisibleFields(t) {
		if !f.IsExported() {
			continue
		}
		k, hasTag := tomlKey(f)
		if f.Anonymous && !hasTag {
			continue
		}
		if hasTag && k == key {
			return f, declaringType(t, f.Index), true
		}
	}
	return reflect.StructField{}, nil, false
}

// declaringType returns the struct type that actually declares the field at the
// given VisibleFields index path (following embeds), for comment lookup.
func declaringType(root reflect.Type, index []int) reflect.Type {
	t := deref(root)
	for _, i := range index[:len(index)-1] {
		t = deref(t.Field(i).Type)
	}
	return t
}

func writeLine(b *strings.Builder, line string) {
	b.WriteString(line)
	b.WriteByte('\n')
}

// writeComment emits a field's doc comment as `#` lines at the given indent.
// Go doc comments conventionally begin with the Go field name; we rewrite that
// leading token to the field's TOML key so the comment reads against the key the
// reader sees below it (e.g. "BackoffDuration is…" -> "source_backoff_duration is…").
func writeComment(b *strings.Builder, indent, key, comment string) {
	lines := docLines(comment)
	if len(lines) > 0 && key != "" {
		if _, rest, found := strings.Cut(lines[0], " "); found {
			lines[0] = key + " " + rest
		} else {
			lines[0] = key
		}
	}
	for _, ln := range lines {
		fmt.Fprintf(b, "%s# %s\n", indent, ln)
	}
}

// --- shared helpers ---

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func tomlKey(sf reflect.StructField) (string, bool) {
	tag := sf.Tag.Get("toml")
	if tag == "" {
		return "", false
	}
	name, _, _ := strings.Cut(tag, ",") // strip options like ",omitempty"
	if name == "" || name == "-" {
		return "", false
	}
	return name, true
}

func splitPath(path string) []string {
	return strings.Split(path, ".")
}

// docLines splits a doc comment into trimmed, non-empty lines.
func docLines(doc string) []string {
	var out []string
	for ln := range strings.SplitSeq(doc, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			out = append(out, ln)
		}
	}
	return out
}
