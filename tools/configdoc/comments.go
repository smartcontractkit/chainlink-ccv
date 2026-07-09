package configdoc

import (
	gopath "path"

	"github.com/invopop/jsonschema"
)

// CommentLookup resolves Go doc comments for struct fields. It is backed by
// invopop/jsonschema's AddGoComments, which parses Go source and indexes every
// type/field doc comment. We use only its comment map — never its JSON Schema
// output — so the fact that jsonschema keys property names off `json` tags
// (which our `toml`-tagged structs mostly lack) is irrelevant here.
//
// invopop keys each comment as `path.Join(base, walkedDir).TypeName.FieldName`,
// where walkedDir is the filesystem directory it walked — so the key embeds the
// directory we passed, not a clean import path. We therefore remember the
// import-path -> directory mapping and reconstruct the same key at lookup time.
type CommentLookup struct {
	comments map[string]string
	dirs     map[string]string // import path -> filesystem dir passed to invopop
}

// LoadComments parses the Go source for the given packages and indexes their
// doc comments. pkgs maps each package's import path to the filesystem
// directory holding its source. Full multi-line comments are retained (not just
// the first-sentence synopsis).
func LoadComments(pkgs map[string]string) (*CommentLookup, error) {
	r := new(jsonschema.Reflector)
	for importPath, dir := range pkgs {
		if err := r.AddGoComments(importPath, dir, jsonschema.WithFullComment()); err != nil {
			return nil, err
		}
	}
	if r.CommentMap == nil {
		r.CommentMap = make(map[string]string)
	}
	return &CommentLookup{comments: r.CommentMap, dirs: pkgs}, nil
}

// Field returns the doc comment for a struct field, identified by its declaring
// type's import path, the type name, and the Go field name. Returns "" if the
// package was not loaded or no comment was found.
func (c *CommentLookup) Field(pkgPath, typeName, fieldName string) string {
	dir, ok := c.dirs[pkgPath]
	if !ok {
		return ""
	}
	prefix := gopath.Join(pkgPath, dir)
	return c.comments[prefix+"."+typeName+"."+fieldName]
}
