package configdoc

import (
	"path/filepath"

	"github.com/smartcontractkit/chainlink-common/x/config/commentparsing"
)

// Files returns a commentparsing.Generator that renders every target of this generator.
//
// Handing the rendering over in this shape is what lets one discovery walk serve several outputs:
// the doc comments a target needs are the same ones a DocComments file or any other reference
// would be built from, so a caller can pass this alongside its own generators to
// [commentparsing.Run] and have all of them written in one pass.
//
// The targets are captured rather than passed in, because a generator receives only the packages
// a walk reached - the values to encode and where each one's output belongs are this package's to
// remember.
func (g *Generator) Files(targets []Target, outDir string) commentparsing.Generator {
	return func(pkgs []commentparsing.Package) (map[string]string, error) {
		comments := commentsFrom(pkgs)
		files := make(map[string]string, len(targets))
		for _, t := range targets {
			content, err := g.render(t, comments)
			if err != nil {
				return nil, err
			}
			files[filepath.Join(outDir, filepath.FromSlash(t.Out))] = content
		}
		return files, nil
	}
}

// Roots returns the values a discovery walk starts from, one per target.
//
// Every target is walked in the same pass so a type shared by two of them is resolved once, which
// is also what keeps a package's file from being written twice.
func Roots(targets []Target) []any {
	roots := make([]any, 0, len(targets))
	for _, t := range targets {
		roots = append(roots, t.New())
	}
	return roots
}
