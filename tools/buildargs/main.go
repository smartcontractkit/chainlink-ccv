// Command buildargs prints the build identity of a checkout for docker builds.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/module"
)

// unset marks a tree that is not a commit we can name: dirty, shallow, or not a repo.
const unset = "unset"

// releaseTag matches root release tags; module tags such as deployment/vX.Y.Z do not match.
const releaseTag = "v[0-9]*.[0-9]*.[0-9]*"

// excludePrerelease drops bare prerelease tags (v0.18.0-rc1), which the glob cannot
// distinguish from releases.
const excludePrerelease = "*-*"

// shortRevLen is the hash length in a Go pseudo-version.
const shortRevLen = 12

type identity struct {
	version string
	sha     string
	warning string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "buildargs:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("buildargs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kv := fs.Bool("kv", false, "print KEY=VALUE lines instead of --build-arg flags")
	repo := fs.String("repo", "", "describe this checkout instead of the current directory")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	id := derive(*repo)
	if id.warning != "" {
		_, _ = fmt.Fprintln(stderr, "buildargs:", id.warning)
	}
	// Without a commit the image carries no identity at all, which the build cannot detect
	// later. Fail here so a broken checkout is loud instead of shipping a nameless image.
	if id.sha == unset {
		return errors.New("no git metadata: cannot identify this build")
	}

	if *kv {
		_, err := fmt.Fprintf(stdout, "VERSION=%s\nCOMMIT_SHA=%s\n", id.version, id.sha)
		return err
	}
	_, err := fmt.Fprintf(stdout, "--build-arg VERSION=%s --build-arg COMMIT_SHA=%s\n", id.version, id.sha)
	return err
}

// derive names the commit at HEAD: its release tag when HEAD is exactly that tag, otherwise a
// Go pseudo-version, and unset when the tree cannot be named by a commit.
func derive(repo string) identity {
	if repo == "" {
		repo = "."
	}
	top, err := git(repo, "rev-parse", "--show-toplevel")
	if err != nil {
		return identity{version: unset, sha: unset}
	}
	repo = top

	sha, err := git(repo, "rev-parse", "HEAD")
	if err != nil {
		return identity{version: unset, sha: unset}
	}

	// A shallow clone cannot see the tags or ancestry a pseudo-version needs, and deriving one
	// anyway would report a build older than the release it follows.
	if shallow, err := git(repo, "rev-parse", "--is-shallow-repository"); err == nil && shallow == "true" {
		return identity{version: unset, sha: sha, warning: "shallow clone: no version can be derived"}
	}

	// Content-based, unlike a stat-only comparison: regenerating a file with identical content
	// (config docs, say) must not read as a modification. -uno keeps untracked build output out.
	status, err := git(repo, "--no-optional-locks", "status", "--porcelain", "--untracked-files=no")
	switch {
	case err != nil:
		return identity{version: unset, sha: sha, warning: "cannot inspect the working tree"}
	case status != "":
		return identity{version: unset, sha: sha, warning: "working tree has uncommitted changes"}
	}

	if tag, err := git(repo, "describe", "--tags", "--exact-match", "--match", releaseTag, "--exclude", excludePrerelease); err == nil {
		return identity{version: tag, sha: sha}
	}

	committedAt, err := git(repo, "log", "-1", "--format=%ct")
	if err != nil {
		return identity{version: unset, sha: sha}
	}
	seconds, err := strconv.ParseInt(committedAt, 10, 64)
	if err != nil {
		return identity{version: unset, sha: sha}
	}

	base, err := git(repo, "describe", "--tags", "--abbrev=0", "--match", releaseTag, "--exclude", excludePrerelease)
	if err != nil {
		base = ""
	}

	rev := sha
	if len(rev) > shortRevLen {
		rev = rev[:shortRevLen]
	}
	version := module.PseudoVersion(major(base), base, time.Unix(seconds, 0).UTC(), rev)
	return identity{version: version, sha: sha}
}

// major returns the major version of a release tag, or v0 when there is no base tag.
func major(base string) string {
	rest := strings.TrimPrefix(base, "v")
	if i := strings.Index(rest, "."); i > 0 {
		return "v" + rest[:i]
	}
	return "v0"
}

// git runs one git command in repo and returns its trimmed stdout.
func git(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...) //nolint:gosec // G204: the repo path and subcommand come from this build tool's own flags
	out, err := cmd.Output()
	if err != nil {
		return "", errors.Join(err, errors.New("git "+strings.Join(args, " ")))
	}
	return strings.TrimSpace(string(out)), nil
}
