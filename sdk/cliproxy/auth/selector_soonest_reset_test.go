package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

var soonestResetTestNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func newSoonestResetTestSelector(now *time.Time) *SoonestResetSelector {
	return &SoonestResetSelector{nowFunc: func() time.Time { return *now }}
}

func unixSeconds(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}

// claudeAuthWithResets builds a Claude credential observed one minute before the test
// clock. A zero reset time leaves that window out of the snapshot.
func claudeAuthWithResets(id string, reset5h, reset7d time.Time) *Auth {
	signals := map[string]string{"Anthropic-Ratelimit-Unified-Status": "allowed"}
	if !reset5h.IsZero() {
		signals["Anthropic-Ratelimit-Unified-5h-Reset"] = unixSeconds(reset5h)
	}
	if !reset7d.IsZero() {
		signals["Anthropic-Ratelimit-Unified-7d-Reset"] = unixSeconds(reset7d)
	}
	return &Auth{
		ID:       id,
		Provider: "claude",
		Quota:    QuotaState{ObservedAt: soonestResetTestNow.Add(-time.Minute), Signals: signals},
	}
}

func pickSoonestResetID(t *testing.T, selector Selector, provider string, auths []*Auth) string {
	t.Helper()
	got, err := selector.Pick(context.Background(), provider, "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil {
		t.Fatalf("Pick() auth = nil")
	}
	return got.ID
}

func TestSoonestResetSelectorPick_PrefersSoonestWeeklyReset(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSoonestResetTestSelector(&now)
	auths := []*Auth{
		// "a" has the sooner 5-hour reset, but its weekly window resets last.
		claudeAuthWithResets("a", now.Add(time.Hour), now.Add(4*24*time.Hour)),
		claudeAuthWithResets("b", now.Add(3*time.Hour), now.Add(24*time.Hour)),
		claudeAuthWithResets("c", now.Add(2*time.Hour), now.Add(2*24*time.Hour)),
	}

	for i := 0; i < 3; i++ {
		if got := pickSoonestResetID(t, selector, "claude", auths); got != "b" {
			t.Fatalf("Pick() #%d auth.ID = %q, want %q", i, got, "b")
		}
	}
}

func TestSoonestResetSelectorPick_ShortWindowBreaksWeeklyTie(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSoonestResetTestSelector(&now)
	weekly := now.Add(2 * 24 * time.Hour)
	auths := []*Auth{
		claudeAuthWithResets("a", now.Add(4*time.Hour), weekly),
		claudeAuthWithResets("b", now.Add(time.Hour), weekly),
	}

	if got := pickSoonestResetID(t, selector, "claude", auths); got != "b" {
		t.Fatalf("Pick() auth.ID = %q, want %q", got, "b")
	}
}

func TestSoonestResetSelectorPick_ProbesUnobservedCredentialOnce(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSoonestResetTestSelector(&now)
	unobserved := &Auth{ID: "b", Provider: "claude"}
	auths := []*Auth{
		claudeAuthWithResets("a", now.Add(time.Hour), now.Add(24*time.Hour)),
		unobserved,
	}

	if got := pickSoonestResetID(t, selector, "claude", auths); got != "b" {
		t.Fatalf("first Pick() auth.ID = %q, want the unobserved credential %q", got, "b")
	}
	// The probe has not answered yet: the known credential is used meanwhile.
	if got := pickSoonestResetID(t, selector, "claude", auths); got != "a" {
		t.Fatalf("second Pick() auth.ID = %q, want %q", got, "a")
	}

	// A credential that still reports nothing is probed again after the interval.
	now = now.Add(soonestResetProbeInterval)
	if got := pickSoonestResetID(t, selector, "claude", auths); got != "b" {
		t.Fatalf("Pick() after the probe interval auth.ID = %q, want %q", got, "b")
	}

	// Once the probe reported a later weekly reset, the sooner one wins.
	unobserved.Quota = claudeAuthWithResets("b", now.Add(time.Hour), now.Add(6*24*time.Hour)).Quota
	unobserved.Quota.ObservedAt = now
	if got := pickSoonestResetID(t, selector, "claude", auths); got != "a" {
		t.Fatalf("Pick() after observation auth.ID = %q, want %q", got, "a")
	}
}

func TestSoonestResetSelectorPick_ProbesCredentialWhoseWindowRolledOver(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSoonestResetTestSelector(&now)
	rolledOver := claudeAuthWithResets("b", time.Time{}, now.Add(-time.Hour))
	rolledOver.Quota.ObservedAt = now.Add(-2 * time.Hour)
	auths := []*Auth{
		claudeAuthWithResets("a", now.Add(time.Hour), now.Add(24*time.Hour)),
		rolledOver,
	}

	if got := pickSoonestResetID(t, selector, "claude", auths); got != "b" {
		t.Fatalf("Pick() auth.ID = %q, want the rolled-over credential %q", got, "b")
	}
}

func TestSoonestResetSelectorPick_CredentialWithoutResetTimeComesLast(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSoonestResetTestSelector(&now)
	auths := []*Auth{
		claudeAuthWithResets("a", time.Time{}, time.Time{}),
		claudeAuthWithResets("b", now.Add(time.Hour), now.Add(6*24*time.Hour)),
	}

	if got := pickSoonestResetID(t, selector, "claude", auths); got != "b" {
		t.Fatalf("Pick() auth.ID = %q, want %q", got, "b")
	}
}

func TestSoonestResetSelectorPick_CodexUsesLongestWindow(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSoonestResetTestSelector(&now)
	observedAt := now.Add(-time.Minute)
	auths := []*Auth{
		{
			ID:       "a",
			Provider: "codex",
			Quota: QuotaState{ObservedAt: observedAt, Signals: map[string]string{
				"X-Codex-Primary-Window-Minutes":        "300",
				"X-Codex-Primary-Reset-After-Seconds":   "600",
				"X-Codex-Secondary-Window-Minutes":      "10080",
				"X-Codex-Secondary-Reset-After-Seconds": strconv.Itoa(5 * 24 * 3600),
			}},
		},
		{
			ID:       "b",
			Provider: "codex",
			Quota: QuotaState{ObservedAt: observedAt, Signals: map[string]string{
				"X-Codex-Primary-Window-Minutes":   "300",
				"X-Codex-Primary-Reset-At":         unixSeconds(now.Add(4 * time.Hour)),
				"X-Codex-Secondary-Window-Minutes": "10080",
				"X-Codex-Secondary-Reset-At":       unixSeconds(now.Add(24 * time.Hour)),
			}},
		},
	}

	if got := pickSoonestResetID(t, selector, "codex", auths); got != "b" {
		t.Fatalf("Pick() auth.ID = %q, want %q", got, "b")
	}
}

func TestSoonestResetSelectorPick_FallsBackToRoundRobinWithoutQuotaSignals(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSoonestResetTestSelector(&now)
	auths := []*Auth{
		{ID: "b", Provider: "gemini"},
		{ID: "a", Provider: "gemini"},
	}

	want := []string{"a", "b", "a"}
	for i, id := range want {
		if got := pickSoonestResetID(t, selector, "gemini", auths); got != id {
			t.Fatalf("Pick() #%d auth.ID = %q, want %q", i, got, id)
		}
	}
}

func TestSoonestResetSelectorPick_SkipsCredentialInCooldown(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSoonestResetTestSelector(&now)
	exhausted := claudeAuthWithResets("a", now.Add(time.Hour), now.Add(24*time.Hour))
	exhausted.Quota.Exceeded = true
	exhausted.Quota.Reason = "credential_quota"
	exhausted.Quota.NextRecoverAt = now.Add(24 * time.Hour)
	auths := []*Auth{
		exhausted,
		claudeAuthWithResets("b", now.Add(time.Hour), now.Add(5*24*time.Hour)),
	}

	if got := pickSoonestResetID(t, selector, "claude", auths); got != "b" {
		t.Fatalf("Pick() auth.ID = %q, want %q", got, "b")
	}
}

func TestSoonestResetSelector_SessionAffinityKeepsBoundCredential(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	soonest := newSoonestResetTestSelector(&now)
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: soonest, TTL: time.Hour})
	a := claudeAuthWithResets("a", now.Add(time.Hour), now.Add(24*time.Hour))
	b := claudeAuthWithResets("b", now.Add(time.Hour), now.Add(3*24*time.Hour))
	auths := []*Auth{a, b}

	pick := func(session string) string {
		t.Helper()
		opts := cliproxyexecutor.Options{Headers: map[string][]string{"X-Session-Id": {session}}}
		got, err := selector.Pick(context.Background(), "claude", "claude-sonnet", opts, auths)
		if err != nil {
			t.Fatalf("Pick() error = %v", err)
		}
		return got.ID
	}

	if got := pick("session-1"); got != "a" {
		t.Fatalf("new session auth.ID = %q, want %q", got, "a")
	}

	// "b" now resets sooner. A new session follows it, the bound session stays put.
	b.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Reset"] = unixSeconds(now.Add(2 * time.Hour))
	if got := pick("session-1"); got != "a" {
		t.Fatalf("bound session auth.ID = %q, want %q", got, "a")
	}
	if got := pick("session-2"); got != "b" {
		t.Fatalf("new session auth.ID = %q, want %q", got, "b")
	}
}
