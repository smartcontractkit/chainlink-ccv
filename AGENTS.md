# AGENTS.md

Guidance for AI agents working in this repository. Read CONTRIBUTING.md for PR title and merge
mechanics. This file records conventions that are easy to get wrong by pattern-matching against
older code that predates them.

## Credentials: secrets file, not environment variables

New credentials are read from the service's secrets file only. Do not add an environment variable
for one.

The `VERIFIER_AGGREGATOR_*` env vars and `CL_DATABASE_URL` exist only for backwards compatibility
with deployments that predate the secrets file. A credential introduced after the file has no such
history, so it gets no env var and there is exactly one place an operator has to look. The
policy-hook HMAC pair is the model: `verifier/pkg/policy/auth.go` resolves it from the secrets
file's `[policy_hook]` table and nowhere else, and a half-supplied pair is a startup error rather
than a silent downgrade to no authentication.

Related: configuration that is marshaled into a Job Distributor job spec (for example the
verifier's `[policy_hook]` TOML section) must never carry a credential value, because the spec is
stored in JD. Reference where the secret lives; keep the value in the secrets file.
