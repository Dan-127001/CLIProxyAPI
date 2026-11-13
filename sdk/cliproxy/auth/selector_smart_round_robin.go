package auth

import (
	"context"
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
// score that says how much each credential should be used right now. The score is the
// product of three factors: weight, urgency and headroom.
//
// Urgency is the share of the longest quota window (the weekly window on Claude and
// Codex subscriptions) that is still unused, divided by the share of that window's time
// that is still left. Above 1 the credential is behind pace and quota would expire
// unused; below 1 it would run out before the reset.
//
// Headroom steers new sessions away from a credential whose short window (5 hours) is
// nearly used up: it is 1 while more than a quarter of that window is left and falls
// linearly to 0 when the window is exhausted.
//
// Weight is the credential's configured weight (default 1).
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
	// value is weight x urgency x headroom.
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

	s.mu.Lock()
	scores := make([]float64, len(available))
	total := 0.0
	for i, auth := range available {
		score := smartRoundRobinScore(auth, now)
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

// smartRoundRobinScore scores one credential for a new session at now.
func smartRoundRobinScore(auth *Auth, now time.Time) smartScore {
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

	windows := quotaWindowResets(auth.Provider, auth.Quota.Signals, auth.Quota.ObservedAt)
	if len(windows) == 0 {
		// Observed, but upstream reports no window to pace against.
		return smartScore{value: weight}
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
	urgency := unused / timeLeft

	headroom := 1.0
	if short.length < long.length && short.usedKnown && short.resetAt.After(now) {
		headroom = clampFloat((1-short.used)/smartShortWindowGuard, 0, 1)
	}
	return smartScore{value: weight * urgency * headroom}
}
