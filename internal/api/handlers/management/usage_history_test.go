package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const claudeUsageSample = `{
  "five_hour": {"utilization": 2.0, "resets_at": "2026-11-14T14:10:00.230056+00:00"},
  "seven_day": {"utilization": 44.0, "resets_at": "2026-11-18T17:00:00.230076+00:00"},
  "seven_day_opus": null,
  "limits": [
    {"kind": "session", "group": "session", "percent": 2, "resets_at": "2026-11-14T14:10:00.230056+00:00", "scope": null},
    {"kind": "weekly_all", "group": "weekly", "percent": 44, "resets_at": "2026-11-18T17:00:00.230076+00:00", "scope": null},
    {"kind": "weekly_scoped", "group": "weekly", "percent": 83, "resets_at": "2026-11-18T17:00:00.230222+00:00", "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}
  ]
}`

const codexUsageSample = `{"rate_limit": {"allowed": true, "primary_window": {"used_percent": 37, "limit_window_seconds": 604800, "reset_after_seconds": 471369, "reset_at": 1795120701}, "secondary_window": null}}`

func TestParseClaudeUsageWindows(t *testing.T) {
	t.Parallel()

	windows, errParse := parseClaudeUsageWindows([]byte(claudeUsageSample))
	if errParse != nil {
		t.Fatalf("parse error: %v", errParse)
	}
	want := []usageHistoryWindow{
		{Name: "5h", Minutes: 300, Used: 2, ResetAt: time.Date(2026, 11, 14, 14, 10, 0, 0, time.UTC).Unix()},
		{Name: "7d", Minutes: 10080, Used: 44, ResetAt: time.Date(2026, 11, 18, 17, 0, 0, 0, time.UTC).Unix()},
		{Name: "Fable", Minutes: 10080, Used: 83, ResetAt: time.Date(2026, 11, 18, 17, 0, 0, 0, time.UTC).Unix(), Scoped: true},
	}
	if len(windows) != len(want) {
		t.Fatalf("windows = %+v, want %+v", windows, want)
	}
	for i := range want {
		if windows[i] != want[i] {
			t.Fatalf("window %d = %+v, want %+v", i, windows[i], want[i])
		}
	}

	// A 5-hour window that is not open is reported as null and left out.
	idle, errIdle := parseClaudeUsageWindows([]byte(`{"five_hour": null, "seven_day": {"utilization": 10, "resets_at": ""}}`))
	if errIdle != nil || len(idle) != 1 || idle[0].Name != "7d" || idle[0].ResetAt != 0 {
		t.Fatalf("idle windows = %+v, err %v", idle, errIdle)
	}
	if _, errBad := parseClaudeUsageWindows([]byte("not json")); errBad == nil {
		t.Fatal("expected an error for a body that is not JSON")
	}
}

func TestParseCodexUsageWindows(t *testing.T) {
	t.Parallel()

	windows, errParse := parseCodexUsageWindows([]byte(codexUsageSample))
	if errParse != nil {
		t.Fatalf("parse error: %v", errParse)
	}
	if len(windows) != 1 || windows[0] != (usageHistoryWindow{Name: "7d", Minutes: 10080, Used: 37, ResetAt: 1795120701}) {
		t.Fatalf("windows = %+v", windows)
	}

	both, errBoth := parseCodexUsageWindows([]byte(`{"rate_limit": {"primary_window": {"used_percent": 5, "limit_window_seconds": 604800, "reset_at": 20}, "secondary_window": {"used_percent": 60, "limit_window_seconds": 18000, "reset_at": 10}}}`))
	if errBoth != nil || len(both) != 2 || both[0].Name != "5h" || both[1].Name != "7d" {
		t.Fatalf("windows = %+v, err %v; want the shorter window first", both, errBoth)
	}
}

// newUsageHistoryTestHandler returns a handler with one Claude and one Codex credential
// whose usage endpoints are served by a local server, and one credential of another provider.
func newUsageHistoryTestHandler(t *testing.T, enabled bool) (*Handler, *int) {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")

	calls := 0
	claudeUsed := 44.0
	var mu sync.Mutex // the credentials are read in parallel
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/claude" && r.Header.Get("Authorization") == "Bearer claude-token" && r.Header.Get("anthropic-beta") != "":
			body := strings.Replace(claudeUsageSample, `"utilization": 44.0`, `"utilization": `+jsonNumber(claudeUsed), 1)
			claudeUsed += 3
			_, _ = w.Write([]byte(body))
		case r.URL.Path == "/codex" && r.Header.Get("Authorization") == "Bearer codex-token":
			_, _ = w.Write([]byte(codexUsageSample))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(upstream.Close)
	previousClaude, previousCodex := usageHistoryClaudeURL, usageHistoryCodexURL
	usageHistoryClaudeURL, usageHistoryCodexURL = upstream.URL+"/claude", upstream.URL+"/codex"
	t.Cleanup(func() { usageHistoryClaudeURL, usageHistoryCodexURL = previousClaude, previousCodex })

	manager := coreauth.NewManager(nil, nil, nil)
	for _, auth := range []*coreauth.Auth{
		{ID: "claude-a.json", Provider: "claude", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "claude-token"}},
		{ID: "codex-a.json", Provider: "codex", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "codex-token"}},
		{ID: "gemini-a.json", Provider: "gemini", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "gemini-token"}},
		{ID: "claude-broken.json", Provider: "claude", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "wrong-token"}},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("failed to register auth record: %v", errRegister)
		}
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir(), UsageHistoryEnabled: enabled}, manager)
	return h, &calls
}

func jsonNumber(value float64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestCollectUsageHistory_StoresReadings(t *testing.T) {
	h, _ := newUsageHistoryTestHandler(t, true)

	first, errFirst := h.collectUsageHistory(context.Background(), "")
	if errFirst != nil {
		t.Fatalf("collect error: %v", errFirst)
	}
	// The credential of another provider and the one whose provider refuses it are left out.
	if len(first.Accounts) != 2 {
		t.Fatalf("accounts = %+v, want the Claude and the Codex credential", first.Accounts)
	}
	claude := first.Accounts["claude-a.json"]
	if claude.Provider != "claude" || len(claude.Windows) != 3 || claude.Windows[1].Used != 44 {
		t.Fatalf("claude reading = %+v", claude)
	}
	if codex := first.Accounts["codex-a.json"]; codex.Provider != "codex" || len(codex.Windows) != 1 || codex.Windows[0].Used != 37 {
		t.Fatalf("codex reading = %+v", codex)
	}

	second, errSecond := h.collectUsageHistory(context.Background(), "reset")
	if errSecond != nil {
		t.Fatalf("second collect error: %v", errSecond)
	}
	if second.Reason != "reset" || second.Accounts["claude-a.json"].Windows[1].Used != 47 {
		t.Fatalf("second reading = %+v", second)
	}

	// Both readings are in the file, one per line, and a new handler reads them back.
	path := filepath.Join(h.configSnapshot().AuthDir, usageHistoryFileName)
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("history file: %v", errRead)
	}
	if lines := strings.Count(string(data), "\n"); lines != 2 {
		t.Fatalf("history file has %d lines, want 2", lines)
	}
	reopened := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: h.configSnapshot().AuthDir}, nil)
	stored, errStored := reopened.usageHistorySince(0)
	if errStored != nil || len(stored) != 2 || stored[1].Reason != "reset" {
		t.Fatalf("stored = %+v, err %v", stored, errStored)
	}
}

func TestUsageHistoryFile_DropsOldAndUnreadableLines(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	dir := t.TempDir()
	now := time.Now().Unix()
	old := now - int64(usageHistoryRetention/time.Second) - 3600
	content := `{"t":` + jsonNumber(float64(old)) + `,"a":{"x":{"p":"claude","w":[]}}}` + "\n" +
		"{\"t\": this line was cut short\n" +
		`{"t":` + jsonNumber(float64(now-60)) + `,"a":{"x":{"p":"claude","w":[{"n":"7d","m":10080,"u":12,"r":5}]}}}` + "\n"
	path := filepath.Join(dir, usageHistoryFileName)
	if errWrite := os.WriteFile(path, []byte(content), 0o600); errWrite != nil {
		t.Fatalf("write: %v", errWrite)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, nil)
	samples, errRead := h.usageHistorySince(0)
	if errRead != nil || len(samples) != 1 || samples[0].Accounts["x"].Windows[0].Used != 12 {
		t.Fatalf("samples = %+v, err %v", samples, errRead)
	}
	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "\n") != 1 {
		t.Fatalf("file after loading = %q, want only the recent reading", data)
	}
}

func TestUsageHistoryEndpoints(t *testing.T) {
	h, calls := newUsageHistoryTestHandler(t, true)

	request := func(method, target, body string, handler func(*gin.Context)) (int, map[string]any) {
		t.Helper()
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(method, target, strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		handler(ctx)
		var payload map[string]any
		if errDecode := json.Unmarshal(rec.Body.Bytes(), &payload); errDecode != nil {
			t.Fatalf("response %q: %v", rec.Body.String(), errDecode)
		}
		return rec.Code, payload
	}

	code, empty := request(http.MethodGet, "/v0/management/usage-history", "", h.GetUsageHistory)
	if code != http.StatusOK || empty["enabled"] != true || len(empty["samples"].([]any)) != 0 || empty["interval_seconds"] != float64(900) {
		t.Fatalf("empty history: %d %+v", code, empty)
	}

	code, collected := request(http.MethodPost, "/v0/management/usage-history/collect", `{"reason":"reset"}`, h.CollectUsageHistory)
	if code != http.StatusOK || collected["sample"] == nil {
		t.Fatalf("collect: %d %+v", code, collected)
	}
	at := int64(collected["sample"].(map[string]any)["t"].(float64))

	code, all := request(http.MethodGet, "/v0/management/usage-history?hours=1", "", h.GetUsageHistory)
	if code != http.StatusOK || len(all["samples"].([]any)) != 1 {
		t.Fatalf("history: %d %+v", code, all)
	}
	code, later := request(http.MethodGet, "/v0/management/usage-history?after="+jsonNumber(float64(at)), "", h.GetUsageHistory)
	if code != http.StatusOK || len(later["samples"].([]any)) != 0 {
		t.Fatalf("history after the reading: %d %+v", code, later)
	}
	if code, _ = request(http.MethodGet, "/v0/management/usage-history?after=x", "", h.GetUsageHistory); code != http.StatusBadRequest {
		t.Fatalf("invalid after: status %d", code)
	}

	// Switched off: nothing is read from the providers.
	off, offCalls := newUsageHistoryTestHandler(t, false)
	code, disabled := request(http.MethodPost, "/v0/management/usage-history/collect", "", off.CollectUsageHistory)
	if code != http.StatusOK || disabled["enabled"] != false || *offCalls != 0 {
		t.Fatalf("collect while off: %d %+v, %d upstream calls", code, disabled, *offCalls)
	}
	if *calls == 0 {
		t.Fatal("expected upstream calls for the enabled handler")
	}
}
