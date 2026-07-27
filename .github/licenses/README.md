# Dependency license policy

`just tidy` runs [google/go-licenses](https://github.com/google/go-licenses) against
production packages in the root Go module. `Repo Hygiene Checks` runs `just tidy` in
CI. It only accepts SPDX identifiers in `allowed-licenses.txt`; an unrecognized,
unlisted, or copyleft license such as GPL therefore fails the required check.

Successful checks suppress `go-licenses` warnings. On failure, the checker writes a
GitHub workflow error annotation and replays the tool output identifying rejected
dependencies.

## Exceptions

`go-licenses` does not recognize every valid license filename, and some licenses need
Legal's dependency-specific approval. `ignored-packages.txt` contains narrowly scoped
package prefixes for those cases. Do not add an entry solely to make a check pass. A
change requires Legal approval, a reason, and the reviewed license in the adjacent
comment. `exception-modules.txt` pins each review to a module version; it also pins the
selected source when a Go `replace` directive is used. Changing either fails the check
until the exception is reviewed and updated. Package dependencies remain checked by
`go-licenses` even when their parent prefix is ignored.

After Legal reviews an updated dependency, run
`tools/bin/check-go-licenses.sh --update-exception-versions` to refresh the version
pins. Review the resulting diff and commit it with the dependency update.

Review exceptions whenever the dependency version changes. Prefer correcting an
upstream license filename or removing the dependency over adding an exception.
