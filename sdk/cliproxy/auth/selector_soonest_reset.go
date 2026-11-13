package auth

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	// soonestResetProbeInterval is how long a credential that was picked to learn its
	// quota windows is left alone before it may be probed again. Credentials that never
	// report quota windows (API keys, for example) would otherwise attract every request.
	soonestResetProbeInterval = 5 * time.Minute
	// soonestResetMaxProbeEntries bounds the probe bookkeeping for removed credentials.
	soonestResetMaxProbeEntries = 1024
)

// SoonestResetSelector prefers the credential whose longest quota window (the weekly
// window on Claude and Codex subscriptions) resets soonest. Quota that is still unused
// when a window resets is lost, so spending the credential closest to its reset first
// wastes the least.
//
// Reset times come from the passive quota snapshot each upstream response leaves on its
// credential (Auth.Quota.Signals). Candidates are ordered as follows:
//
//  1. Credentials whose windows are unknown: never observed, or the observed window has
//     since rolled over. One request is sent to learn the current windows.
//  2. Credentials with a known reset time, soonest long-window reset first. The shortest
//     window (5 hours) breaks ties, then the credential ID.
//  3. Credentials that were observed but report no reset time.
//
// When no candidate has a known or learnable reset time, selection falls back to
// round-robin, which is also what providers without quota headers get.
//
// Exhausted credentials are not handled here: they are in cooldown and are removed from
// the candidates before selection. Credential priority still applies first.
type SoonestResetSelector struct {
	fallback RoundRobinSelector

	mu       sync.Mutex
	probedAt map[string]time.Time
	// nowFunc overrides the clock in tests.
	nowFunc func() time.Time
}

type soonestResetRank int

const (
	soonestResetRankProbe soonestResetRank = iota
	soonestResetRankKnown
	soonestResetRankNoDeadline
)

// quotaWindowReset is one quota window reported by an upstream response.
type quotaWindowReset struct {
	length  time.Duration
	resetAt time.Time
}

type soonestResetCandidate struct {
	rank       soonestResetRank
	longReset  time.Time
	shortReset time.Time
}

// Pick selects the available credential whose long quota window resets soonest.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
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
	var picked *Auth
	var best soonestResetCandidate
	for _, auth := range available {
		candidate := s.classifyLocked(auth, now)
		if picked == nil || soonestResetLess(candidate, best) {
			picked, best = auth, candidate
		}
	}
	if picked != nil && best.rank == soonestResetRankProbe {
		s.markProbedLocked(picked.ID, now)
	}
	s.mu.Unlock()

	if picked == nil || best.rank == soonestResetRankNoDeadline {
		// Nothing to order by: no candidate reports a reset time.
		return s.fallback.Pick(ctx, provider, model, opts, available)
	}
	if best.rank == soonestResetRankProbe {
		log.Debugf("soonest-reset: probing auth=%s provider=%s for its quota windows", picked.ID, picked.Provider)
	} else {
		log.Debugf("soonest-reset: picked auth=%s provider=%s long_reset=%s", picked.ID, picked.Provider, best.longReset.Format(time.RFC3339))
	}
	return picked, nil
}

// ForgetAuth drops the probe bookkeeping of a removed credential.
func (s *SoonestResetSelector) ForgetAuth(authID string) {
	if s == nil || authID == "" {
		return
	}
	s.mu.Lock()
	delete(s.probedAt, authID)
	s.mu.Unlock()
}

// soonestResetLess reports whether a should be picked before b. Equal candidates keep
// the order of the ID-sorted candidate list.
func soonestResetLess(a, b soonestResetCandidate) bool {
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	if a.rank != soonestResetRankKnown {
		return false
	}
	if !a.longReset.Equal(b.longReset) {
		return a.longReset.Before(b.longReset)
	}
	if a.shortReset.IsZero() || b.shortReset.IsZero() {
		// An unknown or already reset short window gives no reason to reorder.
		return false
	}
	return a.shortReset.Before(b.shortReset)
}

// classifyLocked ranks one candidate. Must be called with s.mu held.
func (s *SoonestResetSelector) classifyLocked(auth *Auth, now time.Time) soonestResetCandidate {
	if auth == nil || !ProviderSupportsQuotaObservation(auth.Provider) {
		return soonestResetCandidate{rank: soonestResetRankNoDeadline}
	}
	if auth.Quota.ObservedAt.IsZero() {
		return s.probeOrNoDeadlineLocked(auth.ID, now)
	}

	windows := quotaWindowResets(auth.Provider, auth.Quota.Signals, auth.Quota.ObservedAt)
	if len(windows) == 0 {
		return soonestResetCandidate{rank: soonestResetRankNoDeadline}
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
		// The long window rolled over after it was observed, so its current state is unknown.
		return s.probeOrNoDeadlineLocked(auth.ID, now)
	}
	candidate := soonestResetCandidate{rank: soonestResetRankKnown, longReset: long.resetAt}
	if short.length < long.length && short.resetAt.After(now) {
		candidate.shortReset = short.resetAt
	}
	return candidate
}

// probeOrNoDeadlineLocked ranks a credential with unknown windows: it is probed unless a
// probe was already sent within soonestResetProbeInterval. Must be called with s.mu held.
func (s *SoonestResetSelector) probeOrNoDeadlineLocked(authID string, now time.Time) soonestResetCandidate {
	if probedAt, ok := s.probedAt[authID]; ok && now.Sub(probedAt) < soonestResetProbeInterval {
		return soonestResetCandidate{rank: soonestResetRankNoDeadline}
	}
	return soonestResetCandidate{rank: soonestResetRankProbe}
}

// markProbedLocked records that authID was picked to learn its windows. Must be called
// with s.mu held.
func (s *SoonestResetSelector) markProbedLocked(authID string, now time.Time) {
	if s.probedAt == nil {
		s.probedAt = make(map[string]time.Time)
	}
	if len(s.probedAt) >= soonestResetMaxProbeEntries {
		for id, probedAt := range s.probedAt {
			if now.Sub(probedAt) >= soonestResetProbeInterval {
				delete(s.probedAt, id)
			}
		}
		if len(s.probedAt) >= soonestResetMaxProbeEntries {
			s.probedAt = make(map[string]time.Time)
		}
	}
	s.probedAt[authID] = now
}

// quotaWindowResets extracts the quota windows with a usable reset time from a passive
// quota snapshot. observedAt anchors reset times that upstream reports as a delay.
func quotaWindowResets(provider string, signals map[string]string, observedAt time.Time) []quotaWindowReset {
	if len(signals) == 0 {
		return nil
	}
	var windows []quotaWindowReset
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		for _, window := range []struct {
			name   string
			length time.Duration
		}{
			{"5h", 5 * time.Hour},
			{"7d", 7 * 24 * time.Hour},
		} {
			raw := quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-"+window.name+"-Reset")
			if resetAt, ok := parseQuotaResetTimestamp(raw); ok {
				windows = append(windows, quotaWindowReset{length: window.length, resetAt: resetAt})
			}
		}
	case "codex":
		for _, name := range []string{"Primary", "Secondary"} {
			prefix := "X-Codex-" + name + "-"
			minutes, errMinutes := strconv.ParseFloat(quotaSignalValue(signals, prefix+"Window-Minutes"), 64)
			if errMinutes != nil || minutes <= 0 {
				continue
			}
			resetAt, ok := parseQuotaResetTimestamp(quotaSignalValue(signals, prefix+"Reset-At"))
			if !ok {
				seconds, errSeconds := strconv.ParseFloat(quotaSignalValue(signals, prefix+"Reset-After-Seconds"), 64)
				if errSeconds != nil || seconds < 0 || observedAt.IsZero() {
					continue
				}
				resetAt = observedAt.Add(time.Duration(seconds * float64(time.Second)))
			}
			windows = append(windows, quotaWindowReset{
				length:  time.Duration(minutes * float64(time.Minute)),
				resetAt: resetAt,
			})
		}
	}
	return windows
}

// quotaSignalValue reads a snapshot value by header name, ignoring case.
func quotaSignalValue(signals map[string]string, name string) string {
	if value, ok := signals[name]; ok {
		return strings.TrimSpace(value)
	}
	for key, value := range signals {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// parseQuotaResetTimestamp parses a reset time given as Unix seconds or RFC 3339.
func parseQuotaResetTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if seconds, errParse := strconv.ParseFloat(raw, 64); errParse == nil {
		if seconds <= 0 || seconds > 1e11 {
			return time.Time{}, false
		}
		whole := int64(seconds)
		return time.Unix(whole, int64((seconds-float64(whole))*1e9)), true
	}
	if parsed, errParse := time.Parse(time.RFC3339, raw); errParse == nil {
		return parsed, true
	}
	return time.Time{}, false
}
