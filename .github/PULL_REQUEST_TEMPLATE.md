<!-- ⚠️ PR TITLE must follow Conventional Commits (e.g. `feat(scope): ...`, `fix: ...`).
     It is enforced by CI and becomes the squash commit that drives releases & changelogs.
     Breaking change? Use `feat!:`/`fix!:` and/or a `BREAKING CHANGE:` footer.
     See CONTRIBUTING.md for the allowed types. -->

<!-- Describe what this PR does and why. Focus on the motivation and intent,
     not a restatement of the diff. Link to any relevant issues or discussions. -->

## Description


<!-- Describe how you verified this change works. Include the env file used (e.g.
     env.toml,env-cl.toml), the test or scenario run, and what you observed.
     "Passes CI" alone is not sufficient. -->
## Testing


<!-- Run through this list before requesting review. -->
## Checklist

- [ ] PR title follows Conventional Commits (see `CONTRIBUTING.md`); breaking changes marked with `!` / `BREAKING CHANGE:`
- [ ] Breaking changes documented in changelog (see `changelog` directory)
- [ ] Cross link related PRs (in this or other repositories)
- [ ] `just lint fix` - no new lint errors
- [ ] `just generate` - mocks and protobufs are up to date
