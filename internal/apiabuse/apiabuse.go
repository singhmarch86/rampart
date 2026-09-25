// Package apiabuse detects credential stuffing and token abuse by watching
// for a flood of authentication-failure responses (e.g. repeated 401s) from
// the same client IP against a configured endpoint, then temporarily
// blocking that IP. It doesn't distinguish "wrong password" from "guessed
// token" — both look identical from here (a client racking up failures
// against an auth-gated route), so one mechanism covers both use cases.
package apiabuse

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gauravdeepsingh/rampart/internal/config"
	"github.com/gauravdeepsingh/rampart/internal/events"
)

type compiledRule struct {
	config.APIAbuseRule
	failureCodes map[int]bool
	methods      map[string]bool // nil/empty means "all methods"
}

type ipState struct {
	windowStart  time.Time
	failureCount int
	blockedUntil time.Time
	lastActivity time.Time
}

type ruleState struct {
	mu  sync.Mutex
	ips map[string]*ipState
}

type Guard struct {
	rules  []compiledRule
	states []*ruleState // states[i] tracks rules[i]
	logger *events.Logger
	stop   chan struct{}
}

func New(cfg config.APIAbuseConfig, logger *events.Logger) *Guard {
	g := &Guard{logger: logger, stop: make(chan struct{})}
	for _, r := range cfg.Rules {
		cr := compiledRule{APIAbuseRule: r, failureCodes: make(map[int]bool)}
		for _, code := range r.FailureStatusCodes {
			cr.failureCodes[code] = true
		}
		if len(r.Methods) > 0 {
			cr.methods = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				cr.methods[strings.ToUpper(m)] = true
			}
		}
		g.rules = append(g.rules, cr)
		g.states = append(g.states, &ruleState{ips: make(map[string]*ipState)})
	}
	go g.cleanupLoop()
	return g
}

func (g *Guard) Close() { close(g.stop) }

func (g *Guard) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			for i, rs := range g.states {
				window := g.rules[i].Window
				rs.mu.Lock()
				for ip, st := range rs.ips {
					if now.After(st.blockedUntil) && now.Sub(st.lastActivity) > window {
						delete(rs.ips, ip)
					}
				}
				rs.mu.Unlock()
			}
		case <-g.stop:
			return
		}
	}
}

// Middleware wraps next. It must be positioned so it sees the real upstream
// (or WAF) response status — i.e. it should wrap the handler that already
// includes the WAF and reverse proxy, not the other way around.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	if len(g.rules) == 0 {
		return next
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		for i, rule := range g.rules {
			if !rule.matches(r) {
				continue
			}
			state := g.states[i]

			if blockedFor := state.currentlyBlocked(ip); blockedFor > 0 {
				g.logBlock(r, ip, rule.Name, "IP is temporarily blocked for repeated auth failures")
				rw.Header().Set("Retry-After", strconv.Itoa(blockedFor))
				http.Error(rw, "too many failed attempts", http.StatusTooManyRequests)
				return
			}

			sc := &statusCapture{ResponseWriter: rw}
			next.ServeHTTP(sc, r)

			switch {
			case rule.failureCodes[sc.status]:
				blocked := state.recordFailure(ip, rule.MaxFailures, rule.Window, rule.BlockDuration)
				if blocked {
					g.logBlock(r, ip, rule.Name, "exceeded max failed attempts, IP now temporarily blocked")
				}
			case sc.status >= 200 && sc.status < 300:
				// Only a genuine 2xx success resets the streak. Anything else (a
				// 400 from schema validation, a 403 from the WAF, a 404, ...) is
				// left untouched: if it reset the counter, an attacker could
				// interleave one real guess with one throwaway malformed request
				// to dodge the lockout indefinitely.
				state.recordSuccess(ip)
			}
			return
		}

		// No rule matched this request; pass straight through.
		next.ServeHTTP(rw, r)
	})
}

func (r compiledRule) matches(req *http.Request) bool {
	if r.methods != nil && !r.methods[strings.ToUpper(req.Method)] {
		return false
	}
	return strings.HasPrefix(req.URL.Path, r.PathPrefix)
}

// currentlyBlocked returns remaining block seconds, or 0 if not blocked.
func (rs *ruleState) currentlyBlocked(ip string) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	st, ok := rs.ips[ip]
	if !ok {
		return 0
	}
	remaining := time.Until(st.blockedUntil)
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Seconds()) + 1
}

// recordFailure counts a failure for ip and returns true if this failure
// just crossed the threshold and triggered a new block.
func (rs *ruleState) recordFailure(ip string, maxFailures int, window, blockDuration time.Duration) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	now := time.Now()
	st, ok := rs.ips[ip]
	if !ok || now.Sub(st.windowStart) > window {
		st = &ipState{windowStart: now}
		rs.ips[ip] = st
	}
	st.lastActivity = now
	st.failureCount++
	if st.failureCount >= maxFailures && now.After(st.blockedUntil) {
		st.blockedUntil = now.Add(blockDuration)
		return true
	}
	return false
}

func (rs *ruleState) recordSuccess(ip string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	// A successful (non-failure) response resets the failure streak — this
	// mirrors how account lockouts typically work: consecutive failures matter,
	// not lifetime failures.
	if st, ok := rs.ips[ip]; ok && time.Now().After(st.blockedUntil) {
		delete(rs.ips, ip)
	}
}

func (g *Guard) logBlock(r *http.Request, ip, ruleName, reason string) {
	g.logger.Log(events.Event{
		Action: events.ActionBlock, Layer: "apiabuse", Reason: ruleName + ": " + reason,
		ClientIP: ip, Method: r.Method, Path: r.URL.Path,
	})
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (s *statusCapture) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapture) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
