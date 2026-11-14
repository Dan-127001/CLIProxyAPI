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
		// Urgency counts squared: 7, 1, 0.4 and the bound of 50.
		{"nothing used a day before the weekly reset", claudeAuthWithUsage("a", 0, 1.0/7, -1), 49, false},
		{"on pace", claudeAuthWithUsage("a", 0.3, 0.7, -1), 1, false},
		{"ahead of pace", claudeAuthWithUsage("a", 0.8, 0.5, -1), 0.16, false},
		{"urgency is bounded just before the reset", claudeAuthWithUsage("a", 0, 0.001, -1), 1 / smartMinTimeLeftShare / smartMinTimeLeftShare, false},
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
			got := smartRoundRobinScore(test.auth, "", now)
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
		claudeAuthWithUsage("a", 0, 1.0/7, -1), // urgency 7, score 49
		claudeAuthWithUsage("b", 0.3, 0.7, -1), // urgency 1, score 1
	}

	counts := countSmartPicks(t, selector, "claude", auths, 100)
	if counts["a"] < 97 || counts["a"] > 99 || counts["a"]+counts["b"] != 100 {
		t.Fatalf("picks = %v, want about 98 for a and 2 for b", counts)
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

const smartTestFableModel = "claude-fable-5-2"

// withFableReading records a Fable weekly allowance reading on the credential's model
// state, as a response for that model leaves it. fableUsed is the used share; the window
// resets with the weekly window. observedAgo is how long before the test clock it was read.
func withFableReading(auth *Auth, fableUsed float64, observedAgo time.Duration) *Auth {
	if auth.ModelStates == nil {
		auth.ModelStates = make(map[string]*ModelState)
	}
	auth.ModelStates[smartTestFableModel] = &ModelState{Status: StatusActive, Quota: QuotaState{
		ObservedAt: soonestResetTestNow.Add(-observedAgo),
		Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-7d_oi-Utilization": strconv.FormatFloat(fableUsed, 'f', -1, 64),
			"Anthropic-Ratelimit-Unified-7d_oi-Reset":       auth.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Reset"],
		},
	}}
	return auth
}

func TestSmartRoundRobinScore_ModelWindow(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	// Weekly window on pace (score 1) for every case; only the Fable allowance differs.
	onPace := func() *Auth { return claudeAuthWithUsage("a", 0.3, 0.7, -1) }

	rolledOver := withFableReading(onPace(), 1, time.Minute)
	rolledOver.ModelStates[smartTestFableModel].Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Reset"] = unixSeconds(now.Add(-time.Hour))

	// The credential's own snapshot is newer than the model's and carries the window too.
	newerOnCredential := withFableReading(onPace(), 0.3, time.Hour)
	newerOnCredential.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Utilization"] = "0.86"
	newerOnCredential.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Reset"] = newerOnCredential.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Reset"]

	tests := []struct {
		name  string
		auth  *Auth
		model string
		want  float64
	}{
		// The Fable allowance's own urgency, squared: 0.9/0.7 and 0.14/0.7.
		{"Fable allowance that would expire unused raises the score", withFableReading(onPace(), 0.1, time.Minute), smartTestFableModel, (0.9 / 0.7) * (0.9 / 0.7)},
		{"Fable allowance running out lowers the score", withFableReading(onPace(), 0.86, time.Minute), smartTestFableModel, 0.04},
		{"Fable allowance used up", withFableReading(onPace(), 1, time.Minute), smartTestFableModel, 0},
		{"other models ignore the Fable allowance", withFableReading(onPace(), 1, time.Minute), "", 1},
		{"no Fable reading yet", onPace(), smartTestFableModel, 1},
		{"reading from a window that has rolled over", rolledOver, smartTestFableModel, 1},
		{"newer reading on the credential wins", newerOnCredential, smartTestFableModel, 0.04},
		// Fable urgency 1 (half used, half the time left), week ahead of pace at 0.4.
		{"a week that would run out early scales the score down", withFableReading(claudeAuthWithUsage("a", 0.8, 0.5, -1), 0.5, time.Minute), smartTestFableModel, 0.16},
		// Fable urgency 3.5; the week's urgency of 7 does not add to it.
		{"a week behind pace does not raise the score", withFableReading(claudeAuthWithUsage("a", 0, 1.0/7, -1), 0.5, time.Minute), smartTestFableModel, 12.25},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := smartRoundRobinScore(test.auth, test.model, now)
			if math.Abs(got.value-test.want) > 1e-9 || got.unknown {
				t.Fatalf("score = %+v, want value %v", got, test.want)
			}
		})
	}
}

func TestSmartRoundRobinSelectorPick_FableSessionsAvoidUsedUpAllowance(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	auths := []*Auth{
		// "a" is by far the most urgent on its weekly window, but its Fable allowance is used up.
		withFableReading(claudeAuthWithUsage("a", 0, 1.0/7, -1), 1, time.Minute),
		withFableReading(claudeAuthWithUsage("b", 0.3, 0.7, -1), 0.2, time.Minute),
	}

	pick := func(model string, viaMetadata bool) string {
		t.Helper()
		opts := cliproxyexecutor.Options{}
		arg := model
		if viaMetadata {
			// Without session affinity the selector gets no model argument.
			opts.Metadata = map[string]any{cliproxyexecutor.RequestedModelMetadataKey: model}
			arg = ""
		}
		got, err := selector.Pick(context.Background(), "claude", arg, opts, auths)
		if err != nil {
			t.Fatalf("Pick() error = %v", err)
		}
		return got.ID
	}

	for i := 0; i < 6; i++ {
		if got := pick(smartTestFableModel, i%2 == 1); got != "b" {
			t.Fatalf("Fable pick #%d auth.ID = %q, want %q", i, got, "b")
		}
	}
	// Other models still follow the weekly window: 49 of 50 sessions go to "a".
	counts := map[string]int{}
	for i := 0; i < 50; i++ {
		counts[pick("claude-opus-5-5", false)]++
	}
	if counts["a"] != 49 || counts["b"] != 1 {
		t.Fatalf("Opus picks = %v, want 49 for a and 1 for b", counts)
	}
}

func TestSmartRoundRobinSelectorPick_FableSessionsFollowTheAllowance(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	// Both weeks are on pace. Most of "a"'s Fable allowance would expire unused; "b"'s is
	// nearly gone.
	auths := []*Auth{
		withFableReading(claudeAuthWithUsage("a", 0.3, 0.7, -1), 0.1, time.Minute),
		withFableReading(claudeAuthWithUsage("b", 0.3, 0.7, -1), 0.8, time.Minute),
	}

	count := func(model string, picks int) map[string]int {
		t.Helper()
		counts := map[string]int{}
		for i := 0; i < picks; i++ {
			got, err := selector.Pick(context.Background(), "claude", model, cliproxyexecutor.Options{}, auths)
			if err != nil {
				t.Fatalf("Pick() error = %v", err)
			}
			counts[got.ID]++
		}
		return counts
	}

	// Scores (0.9/0.7)^2 and (0.2/0.7)^2: about 95% of Fable sessions go to "a".
	if counts := count(smartTestFableModel, 40); counts["a"] < 37 || counts["a"] > 39 {
		t.Fatalf("Fable picks = %v, want about 38 for a and 2 for b", counts)
	}
	if counts := count("claude-opus-5-5", 10); counts["a"] != 5 || counts["b"] != 5 {
		t.Fatalf("Opus picks = %v, want 5 each", counts)
	}
}

func TestSmartRoundRobinSelectorPick_CredentialSnapshotNotAppliedToOtherModels(t *testing.T) {
	t.Parallel()

	now := soonestResetTestNow
	selector := newSmartRoundRobinTestSelector(&now)
	// The last response of "a" was a Fable one, so its credential snapshot carries the used-up
	// Fable window. No candidate has a model reading for Opus, so Opus requests ignore it.
	a := claudeAuthWithUsage("a", 0.3, 0.7, -1)
	a.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Utilization"] = "1"
	a.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Reset"] = a.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Reset"]
	auths := []*Auth{a, claudeAuthWithUsage("b", 0.3, 0.7, -1)}

	counts := map[string]int{}
	for i := 0; i < 8; i++ {
		got, err := selector.Pick(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() error = %v", err)
		}
		counts[got.ID]++
	}
	if counts["a"] != 4 || counts["b"] != 4 {
		t.Fatalf("Opus picks = %v, want 4 each", counts)
	}
}
