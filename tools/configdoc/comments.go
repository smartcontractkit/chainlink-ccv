package configdoc

import (
	"github.com/smartcontractkit/chainlink-common/x/config/commentparsing"
)

// CommentLookup resolves Go doc comments for struct fields.
//
// The comments come from chainlink-common/x/config/commentparsing, which reads them from source
// for a type this module declares and from the DocComments method compiled into a dependency for
// one it does not. That second case is why this is not simply a source walk: a config field whose
// type comes from another module has no source tree here to read.
type CommentLookup struct {
	// fields is keyed by package path, type name and field name together, which is all the
	// identity a reflected struct field has.
	fields map[string]string
}

// LoadComments parses the Go source for the given packages and indexes their
// doc comments. pkgs maps each package's import path to the filesystem
// directory holding its source. Full multi-line comments are retained (not just
// the first-sentence synopsis).
//
// Prefer letting [Generator.Render] discover the packages itself: this cannot reach a type from
// another module, because it is given directories and a dependency's source is not among them.
func LoadComments(pkgs map[string]string) (*CommentLookup, error) {
	lookup := &CommentLookup{fields: make(map[string]string)}
	for importPath, dir := range pkgs {
		pkg, err := commentparsing.ParseDir(dir)
		if err != nil {
			return nil, err
		}
		pkg.ImportPath = importPath
		lookup.add(*pkg)
	}
	return lookup, nil
}

// commentsFrom indexes the packages a discovery walk resolved, whatever the origin of each one's
// comments.
func commentsFrom(pkgs []commentparsing.Package) *CommentLookup {
	lookup := &CommentLookup{fields: make(map[string]string)}
	for _, pkg := range pkgs {
		lookup.add(pkg)
	}
	return lookup
}

func (c *CommentLookup) add(pkg commentparsing.Package) {
	for _, typ := range pkg.Types {
		for name, doc := range typ.Fields {
			c.fields[pkg.ImportPath+"."+typ.Name+"."+name] = doc.Comment
		}
	}
}

// Field returns the doc comment for a struct field, identified by its declaring
// type's import path, the type name, and the Go field name. Returns "" if the
// package was not loaded or no comment was found.
func (c *CommentLookup) Field(pkgPath, typeName, fieldName string) string {
	return c.fields[pkgPath+"."+typeName+"."+fieldName]
}
