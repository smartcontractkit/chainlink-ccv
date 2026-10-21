# Admin console request handling

## Executive Summary

- The admin console's no-basic-auth loopback mode now serves only requests whose Host header names a loopback address (`localhost`, `127.0.0.1`, `::1`); other hosts are answered 403.
- Non-GET/HEAD request bodies over 1 MiB are rejected with 413 before dispatch, including chunked bodies.
- The CSRF cookie's Secure flag follows the request's TLS status; `X-Forwarded-Proto` no longer influences it. A new `secure_cookies` config key keeps the flag set behind a TLS-terminating proxy.
- The console HTTP server sets `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` alongside the existing `ReadHeaderTimeout`.
- Behavior changes are internal to `verifier/pkg/admin`; no exported signatures changed, so downstream consumers need no migration.

## AI Adapter Index

| Symbol | Kind | Search | Location | Section |
|---|---|---|---|---|
| `admin.Server.hostAllowlistMiddleware` | behavior-changed | `admin\.NewServer\(` | `verifier/pkg/admin/server.go:132` | [#host-check-in-no-auth-mode](#host-check-in-no-auth-mode) |
| `admin.Server.maxBodyBytesMiddleware` | behavior-changed | `admin\.NewServer\(` | `verifier/pkg/admin/server.go:151` | [#request-body-size-limit](#request-body-size-limit) |
| `admin.Server.csrfMiddleware` | behavior-changed | `admin\.NewServer\(` | `verifier/pkg/admin/server.go:191` | [#csrf-cookie-secure-flag](#csrf-cookie-secure-flag) |
| `admin.Config.SecureCookies` | added | `secure_cookies` | `verifier/pkg/admin/config.go:36` | [#csrf-cookie-secure-flag](#csrf-cookie-secure-flag) |
| `admin.Server.Run` | behavior-changed | `admin\.NewServer\(` | `verifier/pkg/admin/server.go:103` | [#server-timeouts](#server-timeouts) |

## Breaking Changes

*No breaking changes.*

## Host check in no-auth mode

- `buildRouter` (`verifier/pkg/admin/server.go:85`) prepends `hostAllowlistMiddleware` to the middleware chain. It is active only when no `[admin_ui]` credential is configured (`s.basicAuth == nil`, the loopback personal-tool default); with basic auth configured it is a no-op.
- When active, the request's Host (port stripped via `net.SplitHostPort`, tolerating a missing port) must be `localhost`, `127.0.0.1`, `::1`, or `[::1]`; anything else is aborted with 403 before logging, auth, or routing.

## Request body size limit

- `maxBodyBytesMiddleware` (`server.go:151`) runs second in the chain and rejects non-GET/HEAD requests with bodies over 1 MiB with 413 before dispatch: a `Content-Length` over the cap fails fast, and other bodies (including chunked) are read up front under `http.MaxBytesReader`, with the buffered body handed to the handler on success. Gin's form helpers swallow `MaxBytesReader` errors, so wrapping the body without reading it would still let mutations such as recovery cancel/resume through.

## CSRF cookie Secure flag

- The CSRF cookie is marked Secure when `c.Request.TLS != nil` or when the new `secure_cookies` config key is true (`server.go:191`); the `X-Forwarded-Proto: https` branch is dropped. Plain-HTTP loopback deployments still receive a usable (non-Secure) cookie; deployments behind a TLS-terminating proxy set `secure_cookies = true` (see `docs/verifier/admin-console.md`).

## Server timeouts

- `Run` (`server.go:103-110`) now sets `ReadTimeout: 15s`, `WriteTimeout: 60s`, `IdleTimeout: 120s` in addition to the existing `ReadHeaderTimeout: 10s`.

## References

- Stacked on: `changelog/2026-10-20_cursechecker_state_freshness.md`
