package apiabuse

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gauravdeepsingh/rampart/internal/config"
	"github.com/gauravdeepsingh/rampart/internal/events"
)

func newTestGuard(t *testing.T, rules ...config.APIAbuseRule) *Guard {
	t.Helper()
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	g := New(config.APIAbuseConfig{Enabled: true, Rules: rules}, logger)
	t.Cleanup(g.Close)
	return g
}

func upstream(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	})
}

func doRequest(h http.Handler, ip, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = ip + ":12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBlocksAfterMaxFailures(t *testing.T) {
	g := newTestGuard(t, config.APIAbuseRule{
		Name: "login", Methods: []string{"POST"}, PathPrefix: "/login",
		FailureStatusCodes: []int{401}, MaxFailures: 3, Window: time.Minute, BlockDuration: time.Minute,
	})
	h := g.Middleware(upstream(http.StatusUnauthorized))

	for i := 0; i < 3; i++ {
		rec := doRequest(h, "203.0.113.1", http.MethodPost, "/login")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 to pass through, got %d", i, rec.Code)
		}
	}

	rec := doRequest(h, "203.0.113.1", http.MethodPost, "/login")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 4th failure to trigger block (429), got %d", rec.Code)
	}
}

func TestSuccessResetsFailureStreak(t *testing.T) {
	g := newTestGuard(t, config.APIAbuseRule{
		Name: "login", PathPrefix: "/login",
		FailureStatusCodes: []int{401}, MaxFailures: 3, Window: time.Minute, BlockDuration: time.Minute,
	})

	failH := g.Middleware(upstream(http.StatusUnauthorized))
	okH := g.Middleware(upstream(http.StatusOK))

	doRequest(failH, "203.0.113.2", http.MethodPost, "/login")
	doRequest(failH, "203.0.113.2", http.MethodPost, "/login")
	doRequest(okH, "203.0.113.2", http.MethodPost, "/login") // successful login resets streak

	rec := doRequest(failH, "203.0.113.2", http.MethodPost, "/login")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected failure count to have reset after success, got %d (blocked too early)", rec.Code)
	}
}

// TestNonFailureNonSuccessDoesNotResetStreak guards against an evasion where
// an attacker interleaves throwaway requests that return neither a
// configured failure code nor a 2xx success (e.g. a 400 from unrelated
// validation) to keep resetting their failure count and dodge the lockout.
func TestNonFailureNonSuccessDoesNotResetStreak(t *testing.T) {
	g := newTestGuard(t, config.APIAbuseRule{
		Name: "login", PathPrefix: "/login",
		FailureStatusCodes: []int{401}, MaxFailures: 3, Window: time.Minute, BlockDuration: time.Minute,
	})
	failH := g.Middleware(upstream(http.StatusUnauthorized))
	neutralH := g.Middleware(upstream(http.StatusBadRequest)) // neither a tracked failure nor a success

	doRequest(failH, "203.0.113.7", http.MethodPost, "/login")
	doRequest(neutralH, "203.0.113.7", http.MethodPost, "/login") // should NOT reset the streak
	doRequest(failH, "203.0.113.7", http.MethodPost, "/login")
	doRequest(neutralH, "203.0.113.7", http.MethodPost, "/login") // should NOT reset the streak
	doRequest(failH, "203.0.113.7", http.MethodPost, "/login")    // 3rd real failure -> should trigger block

	rec := doRequest(failH, "203.0.113.7", http.MethodPost, "/login")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected interleaved neutral responses to NOT reset the failure streak, got %d (evasion possible)", rec.Code)
	}
}

func TestIsolatedPerIP(t *testing.T) {
	g := newTestGuard(t, config.APIAbuseRule{
		Name: "login", PathPrefix: "/login",
		FailureStatusCodes: []int{401}, MaxFailures: 2, Window: time.Minute, BlockDuration: time.Minute,
	})
	h := g.Middleware(upstream(http.StatusUnauthorized))

	doRequest(h, "203.0.113.3", http.MethodPost, "/login")
	doRequest(h, "203.0.113.3", http.MethodPost, "/login")
	// This IP should now be blocked.
	if rec := doRequest(h, "203.0.113.3", http.MethodPost, "/login"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected .3 to be blocked, got %d", rec.Code)
	}
	// A different IP must be unaffected.
	if rec := doRequest(h, "203.0.113.4", http.MethodPost, "/login"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected .4 to be unaffected by .3's block, got %d", rec.Code)
	}
}

func TestUnrelatedPathNotWatched(t *testing.T) {
	g := newTestGuard(t, config.APIAbuseRule{
		Name: "login", PathPrefix: "/login",
		FailureStatusCodes: []int{401}, MaxFailures: 1, Window: time.Minute, BlockDuration: time.Minute,
	})
	h := g.Middleware(upstream(http.StatusUnauthorized))

	for i := 0; i < 5; i++ {
		rec := doRequest(h, "203.0.113.5", http.MethodGet, "/rest/products")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected unrelated path to pass through unwatched, got %d", rec.Code)
		}
	}
}

func TestMethodFilter(t *testing.T) {
	g := newTestGuard(t, config.APIAbuseRule{
		Name: "login", Methods: []string{"POST"}, PathPrefix: "/login",
		FailureStatusCodes: []int{401}, MaxFailures: 1, Window: time.Minute, BlockDuration: time.Minute,
	})
	h := g.Middleware(upstream(http.StatusUnauthorized))

	// GET isn't watched by this rule, so repeated failures shouldn't block it.
	for i := 0; i < 5; i++ {
		rec := doRequest(h, "203.0.113.6", http.MethodGet, "/login")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected GET (unwatched method) to pass through, got %d", rec.Code)
		}
	}
}
