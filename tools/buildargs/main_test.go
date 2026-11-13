package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// newRepo returns a git repo with one commit on main.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-b", "main")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "test")
	// The host's global git config may sign commits and tags, which would prompt for a key.
	runGit(t, dir, "config", "commit.gpgsign", "false")
	runGit(t, dir, "config", "tag.gpgsign", "false")
	write(t, dir, "f.txt", "one")
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-m", "one")
	return dir
}

func commit(t *testing.T, dir, name string) {
	t.Helper()
	write(t, dir, name, name)
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-m", name)
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// shallowClone clones origin at depth 1, optionally of a specific ref, and returns its path.
func shallowClone(t *testing.T, origin, ref string) string {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "shallow")
	args := []string{"clone", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, "file://"+origin, dest)
	if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	return dest
}

func TestDerive(t *testing.T) {
	t.Run("exact release tag", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")

		id := derive(dir)
		if id.version != "v0.18.0" {
			t.Fatalf("version = %q, want v0.18.0", id.version)
		}
		if len(id.sha) != 40 {
			t.Fatalf("sha = %q, want a full commit", id.sha)
		}
	})

	t.Run("pseudo-version after a tag", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")
		commit(t, dir, "two")

		id := derive(dir)
		if !regexp.MustCompile(`^v0\.18\.1-0\.\d{14}-[0-9a-f]{12}$`).MatchString(id.version) {
			t.Fatalf("version = %q, want a v0.18.1-0.<ts>-<rev> pseudo-version", id.version)
		}
		if !strings.HasSuffix(id.version, id.sha[:12]) {
			t.Fatalf("version %q does not carry commit %q", id.version, id.sha[:12])
		}
	})

	t.Run("pseudo-version with no tag", func(t *testing.T) {
		id := derive(newRepo(t))
		if !regexp.MustCompile(`^v0\.0\.0-\d{14}-[0-9a-f]{12}$`).MatchString(id.version) {
			t.Fatalf("version = %q, want a v0.0.0-<ts>-<rev> pseudo-version", id.version)
		}
	})

	t.Run("module tags are ignored", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "deployment/v0.1.0")
		runGit(t, dir, "tag", "verifier/v0.0.4-rc")

		id := derive(dir)
		if !strings.HasPrefix(id.version, "v0.0.0-") {
			t.Fatalf("version = %q, want the module tags ignored", id.version)
		}
	})

	t.Run("bare prerelease tag is not a release", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0-rc1")

		if id := derive(dir); !strings.HasPrefix(id.version, "v0.0.0-") {
			t.Fatalf("version = %q, want a pseudo-version: a bare prerelease tag is not a release", id.version)
		}
	})

	t.Run("prerelease tag is not a pseudo-version base", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")
		commit(t, dir, "two")
		runGit(t, dir, "tag", "v0.18.1-rc1")
		commit(t, dir, "three")

		id := derive(dir)
		if !regexp.MustCompile(`^v0\.18\.1-0\.\d{14}-[0-9a-f]{12}$`).MatchString(id.version) {
			t.Fatalf("version = %q, want a v0.18.1-0 pseudo-version based on v0.18.0, not the prerelease", id.version)
		}
	})

	t.Run("mtime-only change keeps the version", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")

		// Rewriting a file with unchanged content updates only its metadata, which git treats
		// as clean; a stat-only comparison would call this dirty.
		later := time.Now().Add(time.Hour)
		if err := os.Chtimes(filepath.Join(dir, "f.txt"), later, later); err != nil {
			t.Fatal(err)
		}

		if id := derive(dir); id.version != "v0.18.0" {
			t.Fatalf("version = %q, want v0.18.0: a metadata-only change is not a modification", id.version)
		}
	})

	t.Run("dirty tracked file is unset", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")
		write(t, dir, "f.txt", "modified")

		id := derive(dir)
		if id.version != unset {
			t.Fatalf("version = %q, want %s", id.version, unset)
		}
	})

	t.Run("untracked file keeps the version", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")
		write(t, dir, "build.log", "noise")

		if id := derive(dir); id.version != "v0.18.0" {
			t.Fatalf("version = %q, want v0.18.0", id.version)
		}
	})

	t.Run("shallow clone is unset", func(t *testing.T) {
		origin := newRepo(t)
		runGit(t, origin, "tag", "v0.18.0")
		commit(t, origin, "two")

		id := derive(shallowClone(t, origin, ""))
		if id.version != unset {
			t.Fatalf("version = %q, want %s", id.version, unset)
		}
		if id.warning == "" {
			t.Fatal("want a warning explaining why the version is unset")
		}
	})

	t.Run("shallow clone at a release tag reports the tag", func(t *testing.T) {
		origin := newRepo(t)
		runGit(t, origin, "tag", "v0.18.0")

		// A shallow clone still fetches the tag ref, so the release can be named even though
		// ancestry is missing; only the pseudo-version needs that.
		if id := derive(shallowClone(t, origin, "v0.18.0")); id.version != "v0.18.0" {
			t.Fatalf("version = %q, want v0.18.0", id.version)
		}
	})

	t.Run("tag that is not canonical semver is ignored", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")
		commit(t, dir, "two")
		runGit(t, dir, "tag", "v1.0.0foo")

		// The nearest tag is junk, so the base must come from the last real release.
		id := derive(dir)
		if !strings.HasPrefix(id.version, "v0.18.1-0.") {
			t.Fatalf("version = %q, want a v0.18.1-0.<ts>-<rev> pseudo-version", id.version)
		}
	})

	t.Run("only a non-canonical tag means no base", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v1xxx.2xxx.3xxx")

		if id := derive(dir); !strings.HasPrefix(id.version, "v0.0.0-") {
			t.Fatalf("version = %q, want the junk tag to be ignored", id.version)
		}
	})

	t.Run("prerelease tag is not a release", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.19.0-rc1")

		if id := derive(dir); strings.Contains(id.version, "rc1") {
			t.Fatalf("version = %q, want no prerelease tag", id.version)
		}
	})

	t.Run("not a repo", func(t *testing.T) {
		id := derive(t.TempDir())
		if id.version != unset || id.sha != unset {
			t.Fatalf("identity = %+v, want both unset", id)
		}
	})
}

func TestRun(t *testing.T) {
	output := func(t *testing.T, args ...string) (string, string, error) {
		t.Helper()
		var stdout, stderr strings.Builder
		err := run(args, &stdout, &stderr)
		return stdout.String(), stderr.String(), err
	}

	t.Run("prints build-arg flags", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")

		stdout, _, err := output(t, "--repo", dir)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout, "--build-arg VERSION=v0.18.0") {
			t.Fatalf("stdout = %q, want the release tag", stdout)
		}
	})

	t.Run("prints key value pairs", func(t *testing.T) {
		dir := newRepo(t)
		runGit(t, dir, "tag", "v0.18.0")

		stdout, _, err := output(t, "--repo", dir, "--kv")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(stdout, "VERSION=v0.18.0\nCOMMIT_SHA=") {
			t.Fatalf("stdout = %q, want KEY=VALUE lines", stdout)
		}
	})

	t.Run("fails when the checkout has no git metadata", func(t *testing.T) {
		stdout, _, err := output(t, "--repo", t.TempDir())
		if err == nil {
			t.Fatal("want an error so the build fails instead of shipping an unnamed image")
		}
		if stdout != "" {
			t.Fatalf("stdout = %q, want nothing on failure", stdout)
		}
	})

	t.Run("succeeds on a dirty tree", func(t *testing.T) {
		dir := newRepo(t)
		write(t, dir, "f.txt", "modified")

		stdout, stderr, err := output(t, "--repo", dir)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout, "VERSION=unset") || !strings.Contains(stderr, "uncommitted changes") {
			t.Fatalf("stdout = %q, stderr = %q, want unset plus a warning", stdout, stderr)
		}
	})
}
