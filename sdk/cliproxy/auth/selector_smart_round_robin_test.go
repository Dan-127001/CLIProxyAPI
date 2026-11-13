package auth

import (
	"context"
	"math"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const smartTestWeek = 7 * 24 * time.Hour

func newSmartRoundRobinTestSelector(now *time.Time) *SmartRoundRobinSelector {
	return &SmartRoundRobinSelector{nowFunc: func() time.Time { return *now }}
}

// claudeAuthWithUsage builds a Claude credential observed one minute before the test
// clock. weeklyUsed and weeklyTimeLeft are shares of the weekly window; a negative
// fiveHourUsed leaves the 5-hour window out of the snapshot.
func claudeAuthWithUsage(id string, weeklyUsed, weeklyTimeLeft, fiveHourUsed float64) *Auth {
	now := soonestResetTestNow
	reset5h := time.Time{}
	if fiveHourUsed >= 0 {
		reset5h = now.Add(2 * time.Hour)
	}
	auth := claudeAuthWithResets(id, reset5h, now.Add(time.Duration(weeklyTimeLeft*float64(smartTestWeek))))
	auth.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = strconv.FormatFloat(weeklyUsed, 'f', -1, 64)
	if fiveHourUsed >= 0 {
		auth.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Utilization"] = strconv.FormatFloat(fiveHourUsed, 'f', -1, 64)
	}
	return auth
}

func withWeight(auth *Auth, weight string) *Auth {
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[AttributeWeight] = weight
	return auth
}

func countSmartPicks(t *testing.T, selector Selector, provider string, auths []*Auth, picks int) map[string]int {
	t.Helper()
	counts := make(map[string]int)
	for i := 0; i < picks; i++ {
		counts[pickSoonestResetID(t, selector, provider, auths)]++
	}
	return counts
}

func TestSmartRoundRobinScore(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	rolledOver := claudeAuthWithResets("rolled", time.Time{}, now.Add(-time.Hour))
	rolledOver.Quota.ObservedAt = now.Add(-2 * time.Hour)

	tests := []struct {
		name        string
		auth        *Auth
		want        float64
		wantUnknown bool
	}{
		{"nothing used a day before the weekly reset", claudeAuthWithUsage("a", 0, 1.0/7, -1), 7, false},
		{"on pace", claudeAuthWithUsage("a", 0.3, 0.7, -1), 1, false},
		{"ahead of pace", claudeAuthWithUsage("a", 0.8, 0.5, -1), 0.4, false},
		{"urgency is bounded just before the reset", claudeAuthWithUsage("a", 0, 0.001, -1), 1 / smartMinTimeLeftShare, false},
		{"5-hour window with room left does not matter", claudeAuthWithUsage("a", 0.3, 0.7, 0.5), 1, false},
		{"5-hour window nearly used up", claudeAuthWithUsage("a", 0.3, 0.7, 0.9), 0.4, false},
		{"5-hour window used up", claudeAuthWithUsage("a", 0.3, 0.7, 1), 0, false},
		{"weight multiplies the score", withWeight(claudeAuthWithUsage("a", 0.3, 0.7, -1), "3"), 3, false},
		{"zero weight excludes the credential", withWeight(claudeAuthWithUsage("a", 0.3, 0.7, -1), "0"), 0, false},
		{"never observed", &Auth{ID: "a", Provider: "claude"}, 1, true},
		{"weekly window rolled over", rolledOver, 1, true},
		{"provider without quota headers", withWeight(&Auth{ID: "a", Provider: "gemini"}, "2"), 2, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := smartRoundRobinScore(test.auth, now)
			if math.Abs(got.value-test.want) > 1e-9 || got.unknown != test.wantUnknown {
				t.Fatalf("score = %+v, want value %v unknown %v", got, test.want, test.wantUnknown)
			}
		})
	}
}

func TestSmartRoundRobinSelectorPick_SharesSessionsByScore(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	auths := []*Auth{
		claudeAuthWithUsage("a", 0, 1.0/7, -1), // score 7
		claudeAuthWithUsage("b", 0.3, 0.7, -1), // score 1
	}

	counts := countSmartPicks(t, selector, "claude", auths, 80)
	if counts["a"] < 69 || counts["a"] > 71 || counts["a"]+counts["b"] != 80 {
		t.Fatalf("picks = %v, want about 70 for a and 10 for b", counts)
	}
}

func TestSmartRoundRobinSelectorPick_WeightChangesTheShare(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	auths := []*Auth{
		withWeight(claudeAuthWithUsage("a", 0.3, 0.7, -1), "3"),
		claudeAuthWithUsage("b", 0.3, 0.7, -1),
	}

	counts := countSmartPicks(t, selector, "claude", auths, 40)
	if counts["a"] < 29 || counts["a"] > 31 || counts["a"]+counts["b"] != 40 {
		t.Fatalf("picks = %v, want about 30 for a and 10 for b", counts)
	}
}

func TestSmartRoundRobinSelectorPick_AvoidsExhaustedShortWindow(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	auths := []*Auth{
		// "a" is by far the most urgent on its weekly window, but its 5-hour window is used up.
		claudeAuthWithUsage("a", 0, 1.0/7, 1),
		claudeAuthWithUsage("b", 0.8, 0.5, -1),
	}

	if counts := countSmartPicks(t, selector, "claude", auths, 10); counts["b"] != 10 {
		t.Fatalf("picks = %v, want all 10 for b", counts)
	}
}

func TestSmartRoundRobinSelectorPick_ProbesUnobservedCredentialOnce(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	auths := []*Auth{
		claudeAuthWithUsage("a", 0.3, 0.7, -1),
		{ID: "b", Provider: "claude"},
	}

	if got := pickSoonestResetID(t, selector, "claude", auths); got != "b" {
		t.Fatalf("first Pick() auth.ID = %q, want the unobserved credential %q", got, "b")
	}
	// Until the probe answers, the unobserved credential takes part with a neutral score.
	if counts := countSmartPicks(t, selector, "claude", auths, 10); counts["a"] != 5 || counts["b"] != 5 {
		t.Fatalf("picks after the probe = %v, want 5 each", counts)
	}
}

func TestSmartRoundRobinSelectorPick_WithoutQuotaSignalsIsRoundRobin(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	auths := []*Auth{
		{ID: "a", Provider: "gemini"},
		{ID: "b", Provider: "gemini"},
	}

	want := []string{"a", "b", "a", "b"}
	for i, id := range want {
		if got := pickSoonestResetID(t, selector, "gemini", auths); got != id {
			t.Fatalf("Pick() #%d auth.ID = %q, want %q", i, got, id)
		}
	}
}

func TestSmartRoundRobinSelectorPick_AllScoresZeroStillPicks(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	auths := []*Auth{
		claudeAuthWithUsage("a", 0.3, 0.7, 1),
		claudeAuthWithUsage("b", 0.3, 0.7, 1),
	}

	if counts := countSmartPicks(t, selector, "claude", auths, 4); counts["a"] != 2 || counts["b"] != 2 {
		t.Fatalf("picks = %v, want 2 each", counts)
	}
}

func TestSmartRoundRobinSelector_SessionAffinityKeepsBoundCredential(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	smart := newSmartRoundRobinTestSelector(&now)
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: smart, TTL: time.Hour})
	a := claudeAuthWithUsage("a", 0, 1.0/7, -1)
	b := claudeAuthWithUsage("b", 0.99, 0.9, -1)
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
	// "a" is now nearly used up, so new sessions go to "b"; the bound session stays.
	a.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.999"
	b.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0"
	for i := 0; i < 5; i++ {
		if got := pick("session-1"); got != "a" {
			t.Fatalf("bound session auth.ID = %q, want %q", got, "a")
		}
	}
	if got := pick("session-2"); got != "b" {
		t.Fatalf("new session auth.ID = %q, want %q", got, "b")
	}
}
