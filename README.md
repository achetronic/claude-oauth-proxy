# Claude OAuth Proxy

A zero-dependency local proxy that handles **OAuth PKCE authentication** for Anthropic Teams/Enterprise accounts. It mimics what Claude Code does internally: opens a browser, you log in, and the proxy manages tokens automatically.

## ⚠️ Important

Since January 2026, Anthropic blocked OAuth tokens from **Pro/Max** accounts outside of Claude.ai and Claude Code. **Teams/Enterprise accounts** have legitimate API access — this proxy is built for them.

## Install

Grab a pre-built binary from the [Releases](../../releases) page, or build from source:

```bash
go build -buildvcs=false -o bin/claude-oauth-proxy .
```

Requires Go 1.21+. Zero external dependencies — stdlib only.

## First run

```bash
./bin/claude-oauth-proxy
```

1. Browser opens at `claude.ai/oauth/authorize`
2. Log in with your Teams account
3. Copy the `?code=...` value from the redirect URL and paste it into the terminal
4. Tokens saved to `~/.config/claude-oauth-proxy/tokens.json`
5. Auto-refresh active while the proxy is running

On subsequent runs (without `-relogin`), the proxy loads tokens from disk and skips the login flow entirely.

## Configure Crush CLI

Crush does not support `ANTHROPIC_BASE_URL` (see issue [#2017](https://github.com/charmbracelet/crush/issues/2017)).
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

## Flags

| Flag | Env | Default | Description |
|---|---|---|---|
| `-relogin` | — | `false` | Force browser re-authentication |
| `-fake-key` | `FAKE_API_KEY` | `sk-proxy-local-key` | API key accepted by the proxy |
| `-port` | `PROXY_PORT` | `9999` | Local listen port |

## Token lifecycle

| Situation | Action |
|---|---|
| Valid token on disk | Load directly, skip login |
| Expired token | Automatic refresh |
| Refresh fails | Re-login in browser |
| 401 from Anthropic | Immediate background refresh |

## Endpoints

- `GET  /health` → status + time until token expiry
- `*    /v1/...` → proxied to `api.anthropic.com`

## Performance

The proxy is optimized for minimal latency overhead:

- **TLS connection warm-up** at startup — the first request skips the handshake
- **Per-chunk flushing** for SSE streaming — tokens appear in real time with no buffering delay
- **Keep-alive connection pool** — TLS connections to Anthropic are reused across requests
- **No body double-buffering** — request bodies are passed through as streams
