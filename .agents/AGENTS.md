# AGENTS.md

Agent guide for the `claude-teams-proxy` repository.

## Project Overview

A single-binary Go local proxy that performs OAuth PKCE authentication against Anthropic's Teams/Enterprise accounts and forwards API requests to `api.anthropic.com`. It mimics what Claude Code does internally: opens a browser, the user pastes the auth code, and the proxy manages token persistence and auto-refresh. Intended for use with tools like Crush CLI that accept a custom base URL.

**Only works with Teams/Enterprise accounts.** Pro/Max OAuth tokens have been blocked by Anthropic since January 2026.

## Commands

```bash
# Build binary (output to bin/)
make build
# equivalent: go build -buildvcs=false -o bin/claude-oauth-proxy .

# Run directly without building
go run .

# Force re-authentication
./bin/claude-oauth-proxy -relogin
```

Requires Go 1.21+. **Zero external dependencies** — stdlib only.

## Flags & Environment Variables

| Flag | Env | Default | Description |
|---|---|---|---|
| `-relogin` | — | `false` | Force browser re-auth |
| `-fake-key` | `FAKE_API_KEY` | `sk-proxy-local-key` | Fake API key the proxy accepts from clients |
| `-port` | `PROXY_PORT` | `9999` | Local listen port |

## Code Structure

Single-file project: everything is in `main.go`. Key logical sections marked with ASCII banner comments (`// ── Section ──`):

- **Constants** — OAuth client ID (public, reverse-engineered from Claude Code), endpoints, scopes
- **TokenSet** — token data model with `IsExpired()` (5-min buffer) and `BearerHeader()`
- **Proxy struct** — holds tokens, mutex, config, and the HTTP client
- **main()** — startup sequence: load/refresh/login → save → start warmup+auto-refresh goroutines → HTTP server
- **OAuth PKCE Flow** (`runOAuthFlow`) — opens browser, waits for user to paste the auth code, exchanges for tokens
- **Refresh** — `refreshToken`, `backgroundRefresh` (triggered on 401), `autoRefreshLoop` (ticker every minute)
- **warmupConn** — fires at startup to pre-establish TLS connection with `api.anthropic.com`
- **handleProxy** — manual proxy handler with per-chunk SSE flushing via `http.Flusher`
- **authMiddleware** — validates fake API key from `X-Api-Key` or `Authorization: Bearer` header
- **Persistence** — tokens stored at `~/.config/claude-oauth-proxy/tokens.json` (mode 0600)
- **PKCE helpers** — `generatePKCE()`, `randomBase64URL()`
- **Misc** — `freePort()`, `openBrowser()` (cross-platform), `envOrDefault()`, `envInt()`

## Key Patterns & Conventions

- **Mutex usage**: `sync.RWMutex` on `Proxy`. Use `RLock/RUnlock` for reads, `Lock/Unlock` for writes. Always acquire before accessing `p.tokens`.
- **No external packages**: keep it stdlib-only. Do not add third-party imports.
- **Error handling**: non-fatal errors are logged with `log.Printf`; fatal startup errors use `log.Fatalf`.
- **Streaming**: `streamWithFlush` reads in 4KB chunks and calls `http.Flusher.Flush()` after each write for real-time SSE delivery.
- **Token refresh on 401**: proxy retries the request once after refreshing the token.
- **Callback parsing**: Anthropic may return the auth code as a query param or as a `CODE#STATE` fragment; `parseCallback` handles both forms.
- **Refresh token preservation**: if the token endpoint does not return a new refresh token, the old one is reused.
- **Language**: all user-facing messages, logs, and comments must be in English.
- **Section banners**: use `// ── Section name ──────...` style banners to separate logical sections.

## OAuth Details

- **Client ID**: `9d1c250a-e61b-44d9-88ed-5944d1962f5e` (public, from Claude Code)
- **Auth endpoint**: `https://claude.ai/oauth/authorize`
- **Token endpoint**: `https://console.anthropic.com/v1/oauth/token`
- **Redirect URI**: `https://console.anthropic.com/oauth/code/callback` (user pastes the code manually)
- **Scopes**: `org:create_api_key user:profile user:inference`
- **PKCE**: S256, verifier capped at 128 chars
- **State**: random 32-byte base64url

## Performance Optimizations

- `warmupConn()` fires at startup to pre-establish the TLS connection pool with `api.anthropic.com`
- `DisableCompression: true` on the transport — Anthropic returns JSON/SSE, decompressing in the proxy adds CPU for no benefit
- `MaxIdleConnsPerHost: 10` — keeps connections alive for reuse across requests
- `bytes.NewReader(body)` instead of `strings.NewReader(string(body))` — avoids unnecessary `[]byte→string` copy

## Testing

No test files exist. Manual testing flow:
1. `make build && ./bin/claude-oauth-proxy`
2. Browser opens; authenticate with a Teams account and paste the code
3. Verify banner prints with proxy address and token expiry
4. Test proxy: `curl -H "X-Api-Key: sk-proxy-local-key" http://localhost:9999/health`
5. Point Crush CLI at the proxy and verify inference works

## Client Configuration (Crush CLI)

Crush does **not** support `ANTHROPIC_BASE_URL` (open issue [#2017](https://github.com/charmbracelet/crush/issues/2017)).
Configure the provider directly in `crush.json`:

```json
{
  "providers": {
    "anthropic": {
      "type": "anthropic",
      "base_url": "http://localhost:9999",
      "api_key": "sk-proxy-local-key"
    }
  }
}
```

## Token Lifecycle

| Situation | Action |
|---|---|
| Valid token on disk | Load directly, skip login |
| Expired token on disk | Attempt refresh; re-login on failure |
| 401 from Anthropic API | Refresh token, retry request once |
| Minute ticker fires | Auto-refresh if within 5-minute expiry window |

## Gotchas

- The proxy binds only to `127.0.0.1` (loopback) — not accessible from other hosts by design.
- Token file permissions are `0600`; token dir permissions are `0700`.
- Binaries are built to `bin/` and ignored by git. Download pre-built binaries from GitHub Releases.
