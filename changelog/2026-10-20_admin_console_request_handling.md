# Admin console request handling

## Executive Summary

- The admin console's no-basic-auth loopback mode now serves only requests whose Host header names a loopback address (`localhost`, `127.0.0.1`, `::1`); other hosts are answered 403.
- Non-GET/HEAD request bodies are capped at 1 MiB; a read past the limit fails the form parse and the handler rejects the request.
- The CSRF cookie's Secure flag is now set only when the request itself arrives over TLS; `X-Forwarded-Proto` no longer influences it.
- The console HTTP server sets `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` alongside the existing `ReadHeaderTimeout`.
- Behavior changes are internal to `verifier/pkg/admin`; no exported signatures changed, so downstream consumers need no migration.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `admin.Server.hostAllowlistMiddleware` | behavior-changed | `admin\.NewServer\(` | `verifier/pkg/admin/server.go:132` | [#host-check-in-no-auth-mode](#host-check-in-no-auth-mode) |
| `admin.Server.maxBodyBytesMiddleware` | behavior-changed | `admin\.NewServer\(` | `verifier/pkg/admin/server.go:151` | [#request-body-size-limit](#request-body-size-limit) |
| `admin.Server.csrfMiddleware` | behavior-changed | `admin\.NewServer\(` | `verifier/pkg/admin/server.go:191` | [#csrf-cookie-secure-flag](#csrf-cookie-secure-flag) |
| `admin.Server.Run` | behavior-changed | `admin\.NewServer\(` | `verifier/pkg/admin/server.go:103` | [#server-timeouts](#server-timeouts) |

## Breaking Changes

*No breaking changes.*

## Host check in no-auth mode

- `buildRouter` (`verifier/pkg/admin/server.go:85`) prepends `hostAllowlistMiddleware` to the middleware chain. It is active only when no `[admin_ui]` credential is configured (`s.basicAuth == nil`, the loopback personal-tool default); with basic auth configured it is a no-op.
- When active, the request's Host (port stripped via `net.SplitHostPort`, tolerating a missing port) must be `localhost`, `127.0.0.1`, `::1`, or `[::1]`; anything else is aborted with 403 before logging, auth, or routing.

## Request body size limit

- `maxBodyBytesMiddleware` (`server.go:151`) runs second in the chain and wraps the body in `http.MaxBytesReader` with a 1 MiB cap for methods other than GET/HEAD. A read past the limit fails the form parse, so POST handlers (search, reschedule, recovery) reject the request with a 4xx.

## CSRF cookie Secure flag

- The CSRF cookie is now marked Secure only when `c.Request.TLS != nil` (`server.go:191`). The `X-Forwarded-Proto: https` branch is dropped; plain-HTTP loopback deployments still receive a usable (non-Secure) cookie.

## Server timeouts

- `Run` (`server.go:103-110`) now sets `ReadTimeout: 15s`, `WriteTimeout: 60s`, `IdleTimeout: 120s` in addition to the existing `ReadHeaderTimeout: 10s`.

## References

- Stacked on: `changelog/2026-10-20_cursechecker_state_freshness.md`
