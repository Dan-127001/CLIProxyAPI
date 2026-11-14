package management

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// Usage history: the hub reads every subscription credential's quota usage from its
// provider at a fixed interval and appends the readings to a file. The dashboard derives
// consumption over time and a forecast from them. Readings come from the provider and not
// from the hub's own request headers, so usage of an account outside the hub counts too.

const (
	// usageHistoryInterval is the time between two readings, aligned to the clock.
	usageHistoryInterval = 15 * time.Minute
	// usageHistoryRetention is how long readings are kept.
	usageHistoryRetention = 60 * 24 * time.Hour
	usageHistoryFileName  = "usage-history.jsonl"
	usageHistoryTimeout   = 20 * time.Second
	// usageHistoryStartDelay lets the credentials load before the first reading.
	usageHistoryStartDelay = 15 * time.Second
	// usageHistoryMaxBody bounds a provider's usage response.
	usageHistoryMaxBody = 1 << 20
)

// The providers' usage endpoints; variables so tests can point them at a local server.
var (
	usageHistoryClaudeURL = "https://api.anthropic.com/api/oauth/usage?skip_spend=1"
	usageHistoryCodexURL  = "https://chatgpt.com/backend-api/wham/usage"
)

// usageHistoryWindow is one quota window of a credential at the time of a reading.
type usageHistoryWindow struct {
	// Name is "5h", "7d" and so on for the credential's own windows, and the model's
	// name for a window that only counts one model.
	Name string `json:"n"`
	// Minutes is the window's length.
	Minutes int `json:"m"`
	// Used is the used share of the window in percent.
	Used float64 `json:"u"`
	// ResetAt is when the window ends, in Unix seconds; 0 when the provider gave none.
	ResetAt int64 `json:"r,omitempty"`
	// Scoped marks a window that only counts one model (the Fable weekly allowance).
	Scoped bool `json:"s,omitempty"`
}

type usageHistoryAccount struct {
	Provider string               `json:"p"`
	Windows  []usageHistoryWindow `json:"w"`
}

// usageHistorySample is one reading of all credentials, stored as one line of the file.
type usageHistorySample struct {
	// At is the time of the reading in Unix seconds.
	At int64 `json:"t"`
	// Reason says why a reading was taken outside the schedule, for example "reset".
	Reason string `json:"why,omitempty"`
	// Estimated marks a reading that was reconstructed afterwards instead of read.
	Estimated bool `json:"est,omitempty"`
	// Accounts holds the readings by credential ID.
	Accounts map[string]usageHistoryAccount `json:"a"`
}

// usageHistoryState is the tracker's state on the Handler.
type usageHistoryState struct {
	start sync.Once
	// collectMu serializes readings, so two triggers cannot interleave their upstream calls.
	collectMu sync.Mutex
	// mu guards samples, loaded and path.
	mu      sync.Mutex
	samples []usageHistorySample
	loaded  bool
	path    string
}

// StartUsageHistory starts the background readings. They are taken only while
// usage-history-enabled is set, which is checked before each one, so the setting can be
// changed while the server runs.
func (h *Handler) StartUsageHistory() {
	if h == nil {
		return
	}
	h.usageHistory.start.Do(func() {
		go h.runUsageHistory()
	})
}

func (h *Handler) runUsageHistory() {
	time.Sleep(usageHistoryStartDelay)
	if h.usageHistoryEnabled() {
		if last := h.lastUsageHistorySample(); time.Since(last) >= usageHistoryInterval {
			h.collectUsageHistoryLogged("")
		}
	}
	for {
		next := time.Now().Truncate(usageHistoryInterval).Add(usageHistoryInterval)
		time.Sleep(time.Until(next))
		if h.usageHistoryEnabled() {
			h.collectUsageHistoryLogged("")
		}
	}
}

func (h *Handler) usageHistoryEnabled() bool {
	cfg := h.configSnapshot()
	return cfg != nil && cfg.UsageHistoryEnabled
}

func (h *Handler) collectUsageHistoryLogged(reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*usageHistoryTimeout)
	defer cancel()
	sample, errCollect := h.collectUsageHistory(ctx, reason)
	if errCollect != nil {
		log.Warnf("usage history: reading failed: %v", errCollect)
		return
	}
	log.Debugf("usage history: recorded %d credentials", len(sample.Accounts))
}

// collectUsageHistory reads the usage of every subscription credential now and stores the
// reading. A credential whose provider does not answer is left out of this reading; the
// next one covers the time in between.
func (h *Handler) collectUsageHistory(ctx context.Context, reason string) (usageHistorySample, error) {
	h.usageHistory.collectMu.Lock()
	defer h.usageHistory.collectMu.Unlock()

	h.mu.Lock()
	manager := h.authManager
	h.mu.Unlock()
	if manager == nil {
		return usageHistorySample{}, errors.New("no credentials loaded")
	}

	sample := usageHistorySample{At: time.Now().Unix(), Reason: strings.TrimSpace(reason), Accounts: make(map[string]usageHistoryAccount)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, auth := range manager.List() {
		if auth == nil || auth.ID == "" || !usageHistorySupports(auth.Provider) {
			continue
		}
		wg.Add(1)
		go func(auth *coreauth.Auth) {
			defer wg.Done()
			windows, errRead := h.readProviderUsage(ctx, auth)
			if errRead != nil {
				log.Debugf("usage history: %s: %v", auth.ID, errRead)
				return
			}
			mu.Lock()
			sample.Accounts[auth.ID] = usageHistoryAccount{Provider: strings.ToLower(strings.TrimSpace(auth.Provider)), Windows: windows}
			mu.Unlock()
		}(auth)
	}
	wg.Wait()
	if len(sample.Accounts) == 0 {
		return sample, errors.New("no credential's usage could be read")
	}
	if errAppend := h.appendUsageHistory(sample); errAppend != nil {
		return sample, errAppend
	}
	return sample, nil
}

func usageHistorySupports(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude", "codex":
		return true
	}
	return false
}

// readProviderUsage asks the credential's provider for its current quota windows.
func (h *Handler) readProviderUsage(ctx context.Context, auth *coreauth.Auth) ([]usageHistoryWindow, error) {
	token := tokenValueForAuth(auth)
	if token == "" {
		return nil, errors.New("no access token")
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	target := usageHistoryClaudeURL
	if provider == "codex" {
		target = usageHistoryCodexURL
	}
	ctx, cancel := context.WithTimeout(ctx, usageHistoryTimeout)
	defer cancel()
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if errRequest != nil {
		return nil, errRequest
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if provider == "codex" {
		req.Header.Set("OpenAI-Beta", "codex-1")
		req.Header.Set("Originator", "Codex Desktop")
		if accountID := usageHistoryCodexAccountID(auth); accountID != "" {
			req.Header.Set("Chatgpt-Account-Id", accountID)
		}
	} else {
		req.Header.Set("anthropic-beta", "oauth-2025-04-20")
		req.Header.Set("User-Agent", "claude-cli/2.1.322 (external, cli)")
	}

	client := &http.Client{Timeout: usageHistoryTimeout, Transport: h.apiCallTransport(auth, "")}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("usage history: response body close error: %v", errClose)
		}
	}()
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, usageHistoryMaxBody))
	if errRead != nil {
		return nil, errRead
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider answered HTTP %d", resp.StatusCode)
	}
	if provider == "codex" {
		return parseCodexUsageWindows(body)
	}
	return parseClaudeUsageWindows(body)
}

func usageHistoryCodexAccountID(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	idToken, _ := auth.Metadata["id_token"].(string)
	if idToken = strings.TrimSpace(idToken); idToken == "" {
		return ""
	}
	claims, errParse := codex.ParseJWTToken(idToken)
	if errParse != nil || claims == nil {
		return ""
	}
	return strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
}

// parseClaudeUsageWindows reads the 5-hour and weekly windows and the model-specific
// limits out of Claude's usage response.
func parseClaudeUsageWindows(body []byte) ([]usageHistoryWindow, error) {
	type window struct {
		Utilization *float64 `json:"utilization"`
		ResetsAt    string   `json:"resets_at"`
	}
	var usage struct {
		FiveHour *window `json:"five_hour"`
		SevenDay *window `json:"seven_day"`
		Limits   []struct {
			Group    string   `json:"group"`
			Percent  *float64 `json:"percent"`
			ResetsAt string   `json:"resets_at"`
			Scope    *struct {
				Model *struct {
					DisplayName string `json:"display_name"`
				} `json:"model"`
			} `json:"scope"`
		} `json:"limits"`
	}
	if errDecode := json.Unmarshal(body, &usage); errDecode != nil {
		return nil, fmt.Errorf("unexpected usage response: %w", errDecode)
	}
	windows := make([]usageHistoryWindow, 0, 3)
	add := func(name string, minutes int, w *window) {
		if w == nil || w.Utilization == nil {
			return
		}
		windows = append(windows, usageHistoryWindow{Name: name, Minutes: minutes, Used: *w.Utilization, ResetAt: parseUsageHistoryTime(w.ResetsAt)})
	}
	add("5h", 300, usage.FiveHour)
	add("7d", 7*24*60, usage.SevenDay)
	for _, limit := range usage.Limits {
		if limit.Percent == nil || limit.Scope == nil || limit.Scope.Model == nil {
			continue
		}
		name := strings.TrimSpace(limit.Scope.Model.DisplayName)
		if name == "" {
			continue
		}
		minutes := 7 * 24 * 60
		if limit.Group == "session" {
			minutes = 300
		}
		windows = append(windows, usageHistoryWindow{Name: name, Minutes: minutes, Used: *limit.Percent, ResetAt: parseUsageHistoryTime(limit.ResetsAt), Scoped: true})
	}
	return windows, nil
}

// parseCodexUsageWindows reads the rate limit windows out of Codex's usage response.
func parseCodexUsageWindows(body []byte) ([]usageHistoryWindow, error) {
	type window struct {
		UsedPercent        *float64 `json:"used_percent"`
		LimitWindowSeconds int64    `json:"limit_window_seconds"`
		ResetAt            int64    `json:"reset_at"`
	}
	var usage struct {
		RateLimit struct {
			Primary   *window `json:"primary_window"`
			Secondary *window `json:"secondary_window"`
		} `json:"rate_limit"`
	}
	if errDecode := json.Unmarshal(body, &usage); errDecode != nil {
		return nil, fmt.Errorf("unexpected usage response: %w", errDecode)
	}
	windows := make([]usageHistoryWindow, 0, 2)
	for _, w := range []*window{usage.RateLimit.Primary, usage.RateLimit.Secondary} {
		if w == nil || w.UsedPercent == nil || w.LimitWindowSeconds <= 0 {
			continue
		}
		minutes := int(w.LimitWindowSeconds / 60)
		windows = append(windows, usageHistoryWindow{Name: usageHistoryWindowName(minutes), Minutes: minutes, Used: *w.UsedPercent, ResetAt: w.ResetAt})
	}
	sort.SliceStable(windows, func(i, j int) bool { return windows[i].Minutes < windows[j].Minutes })
	return windows, nil
}

func usageHistoryWindowName(minutes int) string {
	if minutes%(24*60) == 0 {
		return strconv.Itoa(minutes/(24*60)) + "d"
	}
	return strconv.Itoa((minutes+30)/60) + "h"
}

func parseUsageHistoryTime(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	parsed, errParse := time.Parse(time.RFC3339Nano, value)
	if errParse != nil {
		return 0
	}
	return parsed.Unix()
}

// usageHistoryPath returns the history file's path: next to the credential files.
func (h *Handler) usageHistoryPath() (string, error) {
	cfg := h.configSnapshot()
	authDir := ""
	if cfg != nil {
		authDir = cfg.AuthDir
	}
	dir, errResolve := util.ResolveAuthDir(authDir)
	if errResolve != nil {
		return "", errResolve
	}
	return filepath.Join(dir, usageHistoryFileName), nil
}

// loadUsageHistoryLocked reads the history file once. Must be called with usageHistory.mu held.
func (h *Handler) loadUsageHistoryLocked() error {
	path, errPath := h.usageHistoryPath()
	if errPath != nil {
		return errPath
	}
	if h.usageHistory.loaded && h.usageHistory.path == path {
		return nil
	}
	samples, errRead := readUsageHistoryFile(path)
	if errRead != nil {
		return errRead
	}
	cutoff := time.Now().Add(-usageHistoryRetention).Unix()
	kept := samples[:0]
	for _, sample := range samples {
		if sample.At >= cutoff {
			kept = append(kept, sample)
		}
	}
	if len(kept) < len(samples) {
		// Old readings are dropped from the file when it is first read after a start.
		if errWrite := writeUsageHistoryFile(path, kept); errWrite != nil {
			log.Warnf("usage history: could not drop old readings: %v", errWrite)
		}
	}
	h.usageHistory.samples, h.usageHistory.loaded, h.usageHistory.path = kept, true, path
	return nil
}

func readUsageHistoryFile(path string) ([]usageHistorySample, error) {
	data, errRead := os.ReadFile(path)
	if errors.Is(errRead, os.ErrNotExist) {
		return nil, nil
	}
	if errRead != nil {
		return nil, errRead
	}
	var samples []usageHistorySample
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var sample usageHistorySample
		// A line that cannot be read (a write cut short) is skipped.
		if errDecode := json.Unmarshal(line, &sample); errDecode != nil || sample.At <= 0 {
			continue
		}
		samples = append(samples, sample)
	}
	sort.SliceStable(samples, func(i, j int) bool { return samples[i].At < samples[j].At })
	return samples, scanner.Err()
}

func writeUsageHistoryFile(path string, samples []usageHistorySample) error {
	var buffer bytes.Buffer
	for _, sample := range samples {
		line, errEncode := json.Marshal(sample)
		if errEncode != nil {
			return errEncode
		}
		buffer.Write(line)
		buffer.WriteByte('\n')
	}
	temp := path + ".tmp"
	if errWrite := os.WriteFile(temp, buffer.Bytes(), 0o600); errWrite != nil {
		return errWrite
	}
	return os.Rename(temp, path)
}

func (h *Handler) appendUsageHistory(sample usageHistorySample) error {
	h.usageHistory.mu.Lock()
	defer h.usageHistory.mu.Unlock()
	if errLoad := h.loadUsageHistoryLocked(); errLoad != nil {
		return errLoad
	}
	line, errEncode := json.Marshal(sample)
	if errEncode != nil {
		return errEncode
	}
	file, errOpen := os.OpenFile(h.usageHistory.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if errOpen != nil {
		return errOpen
	}
	_, errWrite := file.Write(append(line, '\n'))
	if errClose := file.Close(); errWrite == nil {
		errWrite = errClose
	}
	if errWrite != nil {
		return errWrite
	}
	h.usageHistory.samples = append(h.usageHistory.samples, sample)
	return nil
}

// lastUsageHistorySample returns the time of the latest stored reading.
func (h *Handler) lastUsageHistorySample() time.Time {
	h.usageHistory.mu.Lock()
	defer h.usageHistory.mu.Unlock()
	if errLoad := h.loadUsageHistoryLocked(); errLoad != nil || len(h.usageHistory.samples) == 0 {
		return time.Time{}
	}
	return time.Unix(h.usageHistory.samples[len(h.usageHistory.samples)-1].At, 0)
}

// usageHistorySince returns the stored readings taken after the given Unix time.
func (h *Handler) usageHistorySince(after int64) ([]usageHistorySample, error) {
	h.usageHistory.mu.Lock()
	defer h.usageHistory.mu.Unlock()
	if errLoad := h.loadUsageHistoryLocked(); errLoad != nil {
		return nil, errLoad
	}
	samples := h.usageHistory.samples
	first := sort.Search(len(samples), func(i int) bool { return samples[i].At > after })
	return append([]usageHistorySample(nil), samples[first:]...), nil
}

// GetUsageHistory returns the stored usage readings.
//
//	GET /v0/management/usage-history?hours=168   readings of the last 168 hours
//	GET /v0/management/usage-history?after=<t>   readings taken after Unix time t
func (h *Handler) GetUsageHistory(c *gin.Context) {
	after := time.Now().Add(-7 * 24 * time.Hour).Unix()
	if raw := strings.TrimSpace(c.Query("after")); raw != "" {
		value, errParse := strconv.ParseInt(raw, 10, 64)
		if errParse != nil || value < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid after"})
			return
		}
		after = value
	} else if raw := strings.TrimSpace(c.Query("hours")); raw != "" {
		value, errParse := strconv.Atoi(raw)
		if errParse != nil || value <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hours"})
			return
		}
		after = time.Now().Add(-time.Duration(value) * time.Hour).Unix()
	}
	samples, errRead := h.usageHistorySince(after)
	if errRead != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "usage history could not be read"})
		return
	}
	if samples == nil {
		samples = []usageHistorySample{}
	}
	c.JSON(http.StatusOK, gin.H{"enabled": h.usageHistoryEnabled(), "interval_seconds": int(usageHistoryInterval / time.Second), "samples": samples})
}

// CollectUsageHistory takes a reading now, outside the schedule. The dashboard calls it
// right before and after a quota reset is used, so the reset does not hide consumption.
//
//	POST /v0/management/usage-history/collect   {"reason": "reset"}
func (h *Handler) CollectUsageHistory(c *gin.Context) {
	var body struct {
		Reason string `json:"reason"`
	}
	// The body is optional.
	_ = c.ShouldBindJSON(&body)
	if !h.usageHistoryEnabled() {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if len(reason) > 40 {
		reason = reason[:40]
	}
	sample, errCollect := h.collectUsageHistory(c.Request.Context(), reason)
	if errCollect != nil {
		c.JSON(http.StatusBadGateway, gin.H{"enabled": true, "error": errCollect.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": true, "sample": sample})
}
