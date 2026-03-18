package main

// claude-oauth-proxy — Proxy local con OAuth PKCE automático para cuentas Teams/Enterprise
//
// Uso:
//   go build -o claude-oauth-proxy .
//   ./claude-oauth-proxy
//
// Configura Crush CLI:
//   export ANTHROPIC_API_KEY="sk-proxy-local-key"
//   export ANTHROPIC_BASE_URL="http://localhost:9999"

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Constantes OAuth de Claude Code (públicas, reverse-engineered) ────────────

const (
	claudeClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	authEndpoint   = "https://claude.ai/oauth/authorize"
	tokenEndpoint  = "https://platform.claude.com/v1/oauth/token"
	oauthScopes    = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	anthropicAPI   = "https://api.anthropic.com"
)

// ── Estructuras ───────────────────────────────────────────────────────────────

type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope"`
}

func (t *TokenSet) IsExpired() bool {
	return time.Now().After(t.ExpiresAt.Add(-5 * time.Minute))
}

func (t *TokenSet) BearerHeader() string {
	return "Bearer " + t.AccessToken
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// ── Proxy ─────────────────────────────────────────────────────────────────────

type Proxy struct {
	mu         sync.RWMutex
	refreshMu  sync.Mutex
	tokens     *TokenSet
	tokenFile  string
	fakeAPIKey string
	port       int
	httpClient *http.Client
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	fakeKey := flag.String("fake-key", envOrDefault("FAKE_API_KEY", "sk-proxy-local-key"), "Fake API key accepted from clients")
	port     := flag.Int("port", envInt("PROXY_PORT", 9999), "Local listen port")
	relogin  := flag.Bool("relogin", false, "Force browser re-authentication")
	flag.Parse()

	p := &Proxy{
		fakeAPIKey: *fakeKey,
		port:       *port,
		tokenFile:  tokenFilePath(),
	}

	// 1. Load tokens or authenticate
	if !*relogin {
		if ts, err := loadTokens(p.tokenFile); err == nil {
			if ts.IsExpired() {
				fmt.Println("🔄  Token expired, refreshing...")
				if err := p.refreshToken(ts); err != nil {
					fmt.Printf("⚠️  Refresh failed (%v), re-authenticating...\n", err)
					p.tokens = p.runOAuthFlow()
				}
			} else {
				p.tokens = ts
				fmt.Println("✅  Session loaded from disk")
			}
		} else {
			fmt.Println("🔐  No saved session found. Starting login...")
			p.tokens = p.runOAuthFlow()
		}
	} else {
		fmt.Println("🔐  Forced re-login...")
		p.tokens = p.runOAuthFlow()
	}

	// 2. Save tokens
	_ = saveTokens(p.tokenFile, p.tokens)

	// 3. HTTP client for the proxy
	p.httpClient = &http.Client{
		Timeout: 0,
		Transport: &http.Transport{
			ResponseHeaderTimeout:  5 * time.Minute,
			IdleConnTimeout:        90 * time.Second,
			TLSHandshakeTimeout:    10 * time.Second,
			ExpectContinueTimeout:  1 * time.Second,
			MaxIdleConns:           100,
			MaxIdleConnsPerHost:    10,
			DisableCompression:     true,
		},
	}

	// 4. Auto-refresh loop
	go p.autoRefreshLoop()

	// 5. Pre-warm TLS connection to api.anthropic.com
	go p.warmupConn()

	// 6. HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", p.handleHealth)
	mux.Handle("/", p.authMiddleware(http.HandlerFunc(p.handleProxy)))

	addr := fmt.Sprintf("127.0.0.1:%d", p.port)
	printBanner(addr, p.fakeAPIKey, p.tokens, p.tokenFile)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ── OAuth PKCE Flow ───────────────────────────────────────────────────────────

func (p *Proxy) runOAuthFlow() *TokenSet {
	verifier, challenge := generatePKCE()
	state := randomBase64URL(32)

	redirectURI := "https://platform.claude.com/oauth/code/callback"

	authURL := buildAuthURL(challenge, state, redirectURI)

	fmt.Printf("\n🌐  Opening browser for authentication...\n")
	fmt.Printf("    If it doesn't open, copy this URL:\n\n    %s\n\n", authURL)
	openBrowser(authURL)

	fmt.Printf("⏳  After logging in, Anthropic's page will show a code.\n")
	fmt.Printf("    Copy and paste the code from the URL (the '?code=...' value) here:\n\n")
	fmt.Printf("    Code: ")

	manualCh := make(chan string, 1)
	go func() {
		var input string
		fmt.Scanln(&input)
		if input != "" {
			manualCh <- strings.TrimSpace(input)
		}
	}()

	var raw string
	select {
	case raw = <-manualCh:
		fmt.Println("✅  Code received")
	case <-time.After(5 * time.Minute):
		log.Fatal("❌  Timeout (5 min)")
	}

	// Callback returns "CODE#STATE" or just "CODE"
	code := raw
	if idx := strings.Index(raw, "#"); idx != -1 {
		code = raw[:idx]
	}

	fmt.Println("🔄  Fetching tokens...")
	tokens, err := exchangeCode(code, state, verifier, redirectURI)
	if err != nil {
		log.Fatalf("❌  Failed to fetch tokens: %v", err)
	}
	fmt.Println("🎉  Login complete!")
	return tokens
}

func buildAuthURL(challenge, state, redirectURI string) string {
	p := url.Values{}
	p.Set("client_id", claudeClientID)
	p.Set("response_type", "code")
	p.Set("redirect_uri", redirectURI)
	p.Set("scope", oauthScopes)
	p.Set("code_challenge", challenge)
	p.Set("code_challenge_method", "S256")
	p.Set("state", state)
	return authEndpoint + "?" + p.Encode()
}

func parseCallback(raw string, r *http.Request) (code, state string) {
	// Anthropic returns code#state as a fragment (handled via JS) or as a query param
	code  = r.URL.Query().Get("code")
	state = r.URL.Query().Get("state")

	if code != "" {
		return
	}

	// Fallback: raw may be "CODE#STATE"
	if idx := strings.Index(raw, "#"); idx != -1 {
		return raw[:idx], raw[idx+1:]
	}

	// Or "code=XXX&state=YYY"
	v, _ := url.ParseQuery(raw)
	return v.Get("code"), v.Get("state")
}

func exchangeCode(code, state, verifier, redirectURI string) (*TokenSet, error) {
	return postToken(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     claudeClientID,
		"code":          code,
		"state":         state,
		"redirect_uri":  redirectURI,
		"code_verifier": verifier,
	})
}

// ── Refresh ───────────────────────────────────────────────────────────────────

func (p *Proxy) refreshToken(old *TokenSet) error {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	p.mu.RLock()
	if p.tokens != old {
		p.mu.RUnlock()
		return nil
	}
	p.mu.RUnlock()

	ts, err := postToken(map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     claudeClientID,
		"refresh_token": old.RefreshToken,
	})
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.tokens = ts
	p.mu.Unlock()
	_ = saveTokens(p.tokenFile, ts)
	log.Printf("🔄  Token refreshed, expires in %s", time.Until(ts.ExpiresAt).Round(time.Minute))
	return nil
}

func (p *Proxy) backgroundRefresh() {
	p.mu.RLock()
	ts := p.tokens
	p.mu.RUnlock()
	if err := p.refreshToken(ts); err != nil {
		log.Printf("⚠️  Background refresh failed: %v", err)
	}
}

func (p *Proxy) warmupConn() {
	req, err := http.NewRequest("HEAD", anthropicAPI, nil)
	if err != nil {
		return
	}
	req.Host = "api.anthropic.com"
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func (p *Proxy) autoRefreshLoop() {
	for range time.NewTicker(time.Minute).C {
		p.mu.RLock()
		ts := p.tokens
		p.mu.RUnlock()
		if ts != nil && ts.IsExpired() {
			log.Println("🔄  Auto-refreshing token...")
			if err := p.refreshToken(ts); err != nil {
				log.Printf("⚠️  Auto-refresh failed: %v", err)
			}
		}
	}
}

func (p *Proxy) currentBearer() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tokens.BearerHeader()
}

// ── Token HTTP ────────────────────────────────────────────────────────────────

func postToken(body map[string]string) (*TokenSet, error) {
	oldRT := body["refresh_token"]

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}

		payload, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", tokenEndpoint, strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")

		resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("invalid response: %s", data)
			continue
		}

		var tr tokenResponse
		if err := json.Unmarshal(data, &tr); err != nil {
			lastErr = fmt.Errorf("invalid response: %s", data)
			continue
		}
		if tr.Error != "" {
			return nil, fmt.Errorf("%s: %s", tr.Error, tr.ErrorDesc)
		}
		if tr.AccessToken == "" {
			lastErr = fmt.Errorf("missing access_token: %s", data)
			continue
		}

		rt := tr.RefreshToken
		if rt == "" {
			rt = oldRT
		}

		return &TokenSet{
			AccessToken:  tr.AccessToken,
			RefreshToken: rt,
			TokenType:    tr.TokenType,
			ExpiresIn:    tr.ExpiresIn,
			ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
			Scope:        tr.Scope,
		}, nil
	}
	return nil, lastErr
}

// ── Billing header injection ─────────────────────────────────────────────────

// proxyVersion is sent inside the billing header. Keep it aligned with
// whatever Claude Code version Anthropic expects. Update when needed.
const proxyVersion = "2.1.77"

// billingHeaderPrefix is the marker Anthropic looks for in system[0].
const billingHeaderPrefix = "x-anthropic-billing-header:"

// injectBillingHeader ensures the Messages API body contains the billing
// header that Anthropic requires for Sonnet/Opus models when using OAuth.
// If the first system block already contains it, the body is returned as-is.
// Only applies to JSON bodies that have a "system" field.
func injectBillingHeader(body []byte) []byte {
	// Quick check: if it already contains the billing header, skip parsing
	if bytes.Contains(body, []byte(billingHeaderPrefix)) {
		return body
	}

	// Parse just enough to check/inject the system field
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return body
	}

	// Only inject if there's a "messages" field (i.e., this is a Messages API call)
	if _, ok := msg["messages"]; !ok {
		return body
	}

	billingBlock := map[string]string{
		"type": "text",
		"text": fmt.Sprintf("%s cc_version=%s; cc_entrypoint=cli; cch=00000;", billingHeaderPrefix, proxyVersion),
	}
	billingJSON, _ := json.Marshal(billingBlock)

	sysRaw, hasSystem := msg["system"]

	if !hasSystem || len(bytes.TrimSpace(sysRaw)) == 0 {
		// No system field: create one with just the billing block
		msg["system"] = json.RawMessage(fmt.Sprintf("[%s]", billingJSON))
	} else {
		trimmed := bytes.TrimSpace(sysRaw)
		if trimmed[0] == '[' {
			// system is an array: prepend the billing block
			var sysArr []json.RawMessage
			if err := json.Unmarshal(trimmed, &sysArr); err != nil {
				return body
			}
			sysArr = append([]json.RawMessage{billingJSON}, sysArr...)
			newSys, _ := json.Marshal(sysArr)
			msg["system"] = json.RawMessage(newSys)
		} else if trimmed[0] == '"' {
			// system is a plain string: convert to array with billing + original
			var sysStr string
			if err := json.Unmarshal(trimmed, &sysStr); err != nil {
				return body
			}
			origBlock, _ := json.Marshal(map[string]interface{}{
				"type": "text",
				"text": sysStr,
				"cache_control": map[string]string{"type": "ephemeral", "ttl": "1h"},
			})
			msg["system"] = json.RawMessage(fmt.Sprintf("[%s,%s]", billingJSON, origBlock))
		} else {
			// system is something else (object?): leave as-is
			return body
		}
	}

	newBody, err := json.Marshal(msg)
	if err != nil {
		return body
	}
	log.Println("💉  Injected billing header into system prompt")
	return newBody
}

// ── Proxy handler ────────────────────────────────────────────────────────────

func (p *Proxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(502)
		fmt.Fprintf(w, `{"error":{"message":"%s","type":"proxy_error"}}`, err.Error())
		return
	}

	// Inject billing header for Messages API if not already present
	if r.Method == "POST" && strings.HasPrefix(r.RequestURI, "/v1/messages") {
		body = injectBillingHeader(body)
	}

	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		targetURL := anthropicAPI + r.RequestURI
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(body))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(502)
			fmt.Fprintf(w, `{"error":{"message":"%s","type":"proxy_error"}}`, err.Error())
			return
		}

		for k, vv := range r.Header {
			k2 := strings.ToLower(k)
			if k2 == "x-api-key" || k2 == "authorization" {
				continue
			}
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
		outReq.Header.Set("Authorization", p.currentBearer())

		// Ensure oauth-2025-04-20 is present in Anthropic-Beta (required for OAuth tokens)
		// but preserve any other beta flags the client sends.
		existing := outReq.Header.Get("Anthropic-Beta")
		if existing == "" {
			outReq.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
		} else if !strings.Contains(existing, "oauth-2025-04-20") {
			outReq.Header.Set("Anthropic-Beta", existing+",oauth-2025-04-20")
		}
		// Do NOT set anthropic-version here — let the client decide.
		// If the client doesn't send it, Anthropic uses its default.
		outReq.Host = "api.anthropic.com"

		log.Printf("[→] %s %s (attempt %d/%d)", r.Method, r.RequestURI, attempt+1, maxAttempts)
		log.Printf("    Anthropic-Beta: %s", outReq.Header.Get("Anthropic-Beta"))

		resp, err := p.httpClient.Do(outReq)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(502)
			fmt.Fprintf(w, `{"error":{"message":"%s","type":"proxy_error"}}`, err.Error())
			return
		}

		log.Printf("[←] %d  %s", resp.StatusCode, r.RequestURI)

		// Log the response body on 400 errors for debugging
		if resp.StatusCode == 400 {
			errBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// Decompress gzip if needed
			readable := errBody
			if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
				if gr, err := gzip.NewReader(bytes.NewReader(errBody)); err == nil {
					if decoded, err := io.ReadAll(gr); err == nil {
						readable = decoded
					}
					gr.Close()
				}
			}
			log.Printf("⚠️  400 error body: %s", string(readable))
			// Write the original (possibly compressed) error response to the client
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(400)
			w.Write(errBody)
			return
		}

		if resp.StatusCode == 401 && attempt == 0 {
			resp.Body.Close()
			log.Println("🔄  401 received, refreshing token and retrying...")
			p.mu.RLock()
			ts := p.tokens
			p.mu.RUnlock()
			if err := p.refreshToken(ts); err != nil {
				log.Printf("⚠️  Refresh failed: %v", err)
			}
			continue
		}

		if (resp.StatusCode == 529 || resp.StatusCode == 503) && attempt < maxAttempts-1 {
			wait := retryDelay(resp, attempt)
			resp.Body.Close()
			log.Printf("⏳  %d overloaded, retrying in %s (attempt %d/%d)...", resp.StatusCode, wait.Round(time.Millisecond), attempt+1, maxAttempts)
			select {
			case <-r.Context().Done():
				return
			case <-time.After(wait):
			}
			continue
		}

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		streaming := isStreaming(resp)
		if streaming {
			flusher, ok := w.(http.Flusher)
			if ok {
				streamWithFlush(resp.Body, w, flusher)
				resp.Body.Close()
				return
			}
		}
		io.Copy(w, resp.Body)
		resp.Body.Close()
		return
	}
}

func retryDelay(resp *http.Response, attempt int) time.Duration {
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	base := time.Duration(1<<uint(attempt)) * time.Second
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	return base
}

func isStreaming(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/event-stream") || strings.Contains(ct, "application/x-ndjson")
}

func streamWithFlush(src io.Reader, dst io.Writer, flusher http.Flusher) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n])
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}
}

// ── Middleware & handlers ─────────────────────────────────────────────────────

func (p *Proxy) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Api-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if key != p.fakeAPIKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			fmt.Fprintln(w, `{"error":{"message":"Invalid API key","type":"authentication_error"}}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Proxy) handleHealth(w http.ResponseWriter, _ *http.Request) {
	p.mu.RLock()
	exp := time.Until(p.tokens.ExpiresAt).Round(time.Minute).String()
	p.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","token_expires_in":"%s"}`, exp)
}

// ── Persistence ───────────────────────────────────────────────────────────────

func tokenFilePath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".config", "claude-oauth-proxy")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "tokens.json")
}

func saveTokens(path string, ts *TokenSet) error {
	data, _ := json.MarshalIndent(ts, "", "  ")
	return os.WriteFile(path, data, 0600)
}

func loadTokens(path string) (*TokenSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ts TokenSet
	if err := json.Unmarshal(data, &ts); err != nil {
		return nil, err
	}
	if ts.AccessToken == "" {
		return nil, fmt.Errorf("empty token file")
	}
	return &ts, nil
}

// ── PKCE ──────────────────────────────────────────────────────────────────────

func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 64)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	if len(verifier) > 128 {
		verifier = verifier[:128]
	}
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func randomBase64URL(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	s := base64.RawURLEncoding.EncodeToString(b)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ── Misc ──────────────────────────────────────────────────────────────────────

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 19999
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func openBrowser(u string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{u}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", u}
	default:
		cmd, args = "xdg-open", []string{u}
	}
	exec.Command(cmd, args...).Start()
}

func envOrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return def
}

func printBanner(addr, fakeKey string, ts *TokenSet, tokenFile string) {
	fmt.Printf("\n")
	fmt.Printf("  ╔═══════════════════════════════════════════════╗\n")
	fmt.Printf("  ║     Claude OAuth Proxy  —  ready! 🚀          ║\n")
	fmt.Printf("  ╚═══════════════════════════════════════════════╝\n\n")
	fmt.Printf("  🌐  Proxy:        http://%s\n", addr)
	fmt.Printf("  🔑  Fake key:     %s\n", fakeKey)
	fmt.Printf("  ⏱️   Token exp:    %s\n", ts.ExpiresAt.Format("15:04:05 (MST)"))
	fmt.Printf("  💾  Tokens at:    %s\n\n", tokenFile)
	fmt.Printf("  Configure Crush CLI (crush.json):\n\n")
	fmt.Printf("    {\"providers\":{\"anthropic\":{\"type\":\"anthropic\",\n")
	fmt.Printf("      \"base_url\":\"http://%s\",\"api_key\":%q}}}\n\n", addr, fakeKey)
	fmt.Printf("  To re-authenticate:  ./claude-oauth-proxy -relogin\n\n")
}

// ── Success HTML ──────────────────────────────────────────────────────────────

const successHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Done!</title>
<style>
body{font-family:system-ui,sans-serif;display:flex;align-items:center;
     justify-content:center;height:100vh;margin:0;background:#0f172a;color:#e2e8f0}
.card{text-align:center;padding:2rem 3rem;background:#1e293b;
      border-radius:1rem;box-shadow:0 4px 32px #0005}
.icon{font-size:3rem}.h1{margin:.5rem 0 .25rem;font-size:1.5rem}
p{color:#94a3b8;margin:0}
</style>
</head>
<body>
<div class="card">
  <div class="icon">✅</div>
  <h1>Authentication complete!</h1>
  <p>You can close this window and return to the terminal.</p>
</div>
</body>
</html>`
