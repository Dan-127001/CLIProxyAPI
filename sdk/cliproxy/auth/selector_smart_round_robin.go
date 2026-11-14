package auth

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	// smartMinTimeLeftShare bounds the urgency of a window that is about to reset, so a
	// credential minutes before its reset cannot take an unbounded share.
	smartMinTimeLeftShare = 0.02
	// smartShortWindowGuard is the remaining share of the short window below which new
	// sessions are steered away, reaching zero when the window is used up.
	smartShortWindowGuard = 0.25
	// smartMaxPoolKeys bounds the number of credit pools kept in memory.
	smartMaxPoolKeys = 4096
)

// SmartRoundRobinSelector spreads new sessions across credentials in proportion to a
// score that says how much each credential should be used right now:
//
//	score = weight x urgency^2 x headroom
//
// Urgency is the share of the longest quota window (the weekly window on Claude and
// Codex subscriptions) that is still unused, divided by the share of that window's time
// that is still left. Above 1 the credential is behind pace and quota would expire
// unused; below 1 it would run out before the reset. It counts squared, so quota that is
// about to expire takes most new sessions and quota that keeps for later is spared.
//
// Headroom steers new sessions away from a credential whose short window (5 hours) is
// nearly used up: it is 1 while more than a quarter of that window is left and falls
// linearly to 0 when the window is exhausted.
//
// Weight is the credential's configured weight (default 1).
//
// Some models have a quota window of their own next to the credential's windows (the
// Fable weekly allowance on Claude subscriptions). For a request to such a model, urgency
// is that of the model's window, so sessions for it go where its allowance would expire
// unused and skip a credential where it is used up. It is scaled down when the credential
// itself would run out before its reset.
//
// Selection is a smooth weighted round-robin over these scores, so a burst of parallel
// sessions is spread instead of landing on one credential before its usage is observed
// again. Scores come from the passive quota snapshot upstream responses leave on each
// credential; a credential whose windows are unknown gets one request to learn them,
// and one that reports no windows is scored by its weight alone.
//
// Exhausted credentials are in cooldown and are removed before selection. Credential
// priority still applies first, and session affinity keeps running sessions in place.
type SmartRoundRobinSelector struct {
	fallback RoundRobinSelector

	mu     sync.Mutex
	probes quotaProbeTracker
	// credits holds the smooth round-robin credit of each credential, per pool.
	credits map[string]map[string]float64
	// nowFunc overrides the clock in tests.
	nowFunc func() time.Time
}

// smartScore is the routing score of one credential.
type smartScore struct {
	// value is weight x urgency^2 x headroom.
	value float64
	// unknown is set when the credential's windows must be learned with a request first.
	unknown bool
}

// Pick selects a credential for a new session in proportion to the credential scores.
func (s *SmartRoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	if s.nowFunc != nil {
		now = s.nowFunc()
	}
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)

	scoreModel := smartModelWithOwnWindow(smartRequestModel(model, opts), auths)

	s.mu.Lock()
	scores := make([]float64, len(available))
	total := 0.0
	for i, auth := range available {
		score := smartRoundRobinScore(auth, scoreModel, now)
		if score.unknown && s.probes.due(auth.ID, now) {
			s.probes.mark(auth.ID, now)
			s.mu.Unlock()
			log.Debugf("smart-round-robin: probing auth=%s provider=%s for its quota windows", auth.ID, auth.Provider)
			return auth, nil
		}
		scores[i] = score.value
		total += score.value
	}
	if total <= 0 {
		s.mu.Unlock()
		// No credential has a positive score; any of them is as good as another.
		return s.fallback.Pick(ctx, provider, model, opts, available)
	}

	pool := s.poolLocked(provider + ":" + canonicalModelLookupKey(model))
	var picked *Auth
	pickedCredit := 0.0
	for i, auth := range available {
		if scores[i] <= 0 {
			continue
		}
		// The clamp keeps a credential whose score just changed sharply from owing, or
		// being owed, more than one full round.
		credit := clampFloat(pool[auth.ID]+scores[i], -total, total)
		pool[auth.ID] = credit
		if picked == nil || credit > pickedCredit {
			picked, pickedCredit = auth, credit
		}
	}
	pool[picked.ID] = pickedCredit - total
	if len(pool) > 4*len(available)+16 {
		prunePoolCredits(pool, available)
	}
	s.mu.Unlock()

	log.Debugf("smart-round-robin: picked auth=%s provider=%s share=%.0f%%", picked.ID, picked.Provider, 100*scoreOf(available, scores, picked)/total)
	return picked, nil
}

// ForgetAuth drops the bookkeeping of a removed credential.
func (s *SmartRoundRobinSelector) ForgetAuth(authID string) {
	if s == nil || authID == "" {
		return
	}
	s.mu.Lock()
	s.probes.forget(authID)
	for _, pool := range s.credits {
		delete(pool, authID)
	}
	s.mu.Unlock()
}

// poolLocked returns the credit pool for key. Must be called with s.mu held.
func (s *SmartRoundRobinSelector) poolLocked(key string) map[string]float64 {
	if s.credits == nil || (len(s.credits) >= smartMaxPoolKeys && s.credits[key] == nil) {
		s.credits = make(map[string]map[string]float64)
	}
	pool := s.credits[key]
	if pool == nil {
		pool = make(map[string]float64)
		s.credits[key] = pool
	}
	return pool
}

func prunePoolCredits(pool map[string]float64, available []*Auth) {
	keep := make(map[string]struct{}, len(available))
	for _, auth := range available {
		keep[auth.ID] = struct{}{}
	}
	for id := range pool {
		if _, ok := keep[id]; !ok {
			delete(pool, id)
		}
	}
}

func scoreOf(available []*Auth, scores []float64, picked *Auth) float64 {
	for i, auth := range available {
		if auth == picked {
			return scores[i]
		}
	}
	return 0
}

func clampFloat(value, low, high float64) float64 {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

// smartRequestModel returns the model a selection is for. With session affinity the
// selector receives it directly; otherwise it is taken from the request metadata.
func smartRequestModel(model string, opts cliproxyexecutor.Options) string {
	if model = strings.TrimSpace(model); model != "" {
		return model
	}
	requested, _ := opts.Metadata[cliproxyexecutor.RequestedModelMetadataKey].(string)
	return strings.TrimSpace(requested)
}

// modelQuotaWindow extracts the model-specific quota window from a passive quota snapshot.
// Claude subscriptions report the Fable weekly allowance as the "7d_oi" window.
func modelQuotaWindow(provider string, quota QuotaState) (quotaWindowReset, bool) {
	if !strings.EqualFold(strings.TrimSpace(provider), "claude") || len(quota.Signals) == 0 {
		return quotaWindowReset{}, false
	}
	resetAt, okReset := parseQuotaResetTimestamp(quotaSignalValue(quota.Signals, "Anthropic-Ratelimit-Unified-7d_oi-Reset"))
	used, okUsed := parseQuotaUsedShare(quotaSignalValue(quota.Signals, "Anthropic-Ratelimit-Unified-7d_oi-Utilization"), 1)
	if !okReset || !okUsed {
		return quotaWindowReset{}, false
	}
	return quotaWindowReset{length: 7 * 24 * time.Hour, resetAt: resetAt, used: used, usedKnown: true}, true
}

// modelStateQuota returns the quota snapshot auth keeps for model.
func modelStateQuota(auth *Auth, model string) (QuotaState, bool) {
	if auth == nil || model == "" {
		return QuotaState{}, false
	}
	for stateModel, state := range auth.ModelStates {
		if state != nil && sameCanonicalModelKey(stateModel, model) {
			return state.Quota, true
		}
	}
	return QuotaState{}, false
}

// smartModelWithOwnWindow returns model when responses for it are known to carry a
// model-specific quota window on one of the candidates, and "" otherwise. The window is
// only reported with responses for such a model, so a credential-level snapshot holding
// it must not be applied to requests for other models.
func smartModelWithOwnWindow(model string, auths []*Auth) string {
	if model == "" {
		return ""
	}
	for _, auth := range auths {
		if quota, ok := modelStateQuota(auth, model); ok {
			if _, okWindow := modelQuotaWindow(auth.Provider, quota); okWindow {
				return model
			}
		}
	}
	return ""
}

// smartModelWindow returns auth's latest reading of the model-specific window: from the
// model's own snapshot or from the credential's, whichever was observed last.
func smartModelWindow(auth *Auth, model string) (quotaWindowReset, bool) {
	var best quotaWindowReset
	var bestAt time.Time
	found := false
	consider := func(quota QuotaState) {
		window, ok := modelQuotaWindow(auth.Provider, quota)
		if ok && (!found || quota.ObservedAt.After(bestAt)) {
			best, bestAt, found = window, quota.ObservedAt, true
		}
	}
	if quota, ok := modelStateQuota(auth, model); ok {
		consider(quota)
	}
	consider(auth.Quota)
	return best, found
}

// smartRoundRobinScore scores one credential for a new session at now. model is the
// request's model when it has a quota window of its own, and "" otherwise.
func smartRoundRobinScore(auth *Auth, model string, now time.Time) smartScore {
	if auth == nil {
		return smartScore{}
	}
	weight := float64(authWeight(auth))
	if weight <= 0 {
		return smartScore{}
	}
	if !ProviderSupportsQuotaObservation(auth.Provider) {
		return smartScore{value: weight}
	}
	if auth.Quota.ObservedAt.IsZero() {
		return smartScore{value: weight, unknown: true}
	}

	// modelUrgency replaces the credential's urgency by that of the model's own window,
	// scaled down when the credential itself is ahead of pace (urgency below 1). A reading
	// whose window has rolled over says nothing about the current one and is ignored, as
	// is a credential the window has not been read for yet.
	modelUrgency := func(urgency float64) float64 {
		if model == "" {
			return urgency
		}
		window, ok := smartModelWindow(auth, model)
		if !ok || !window.resetAt.After(now) {
			return urgency
		}
		timeLeft := clampFloat(float64(window.resetAt.Sub(now))/float64(window.length), smartMinTimeLeftShare, 1)
		return (1 - window.used) / timeLeft * math.Min(1, urgency)
	}
	// score squares the urgency, so the split leans towards quota that is about to expire.
	score := func(urgency, headroom float64) smartScore {
		return smartScore{value: weight * urgency * urgency * headroom}
	}

	windows := quotaWindowResets(auth.Provider, auth.Quota.Signals, auth.Quota.ObservedAt)
	if len(windows) == 0 {
		// Observed, but upstream reports no credential window to pace against.
		return score(modelUrgency(1), 1)
	}
	long, short := windows[0], windows[0]
	for _, window := range windows[1:] {
		if window.length > long.length {
			long = window
		}
		if window.length < short.length {
			short = window
		}
	}
	if !long.resetAt.After(now) {
		// The long window rolled over after it was observed, so its usage is unknown.
		return smartScore{value: weight, unknown: true}
	}

	unused := 1.0
	if long.usedKnown {
		unused = 1 - long.used
	}
	timeLeft := clampFloat(float64(long.resetAt.Sub(now))/float64(long.length), smartMinTimeLeftShare, 1)
	urgency := modelUrgency(unused / timeLeft)

	headroom := 1.0
	if short.length < long.length && short.usedKnown && short.resetAt.After(now) {
		headroom = clampFloat((1-short.used)/smartShortWindowGuard, 0, 1)
	}
	return score(urgency, headroom)
}
