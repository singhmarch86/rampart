package hostguard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/singhmarch86/rampart/internal/events"
)

func mustNew(t *testing.T, allowed ...string) *Guard {
	t.Helper()
	g, err := New(allowed)
	if err != nil {
		t.Fatalf("New(%v): %v", allowed, err)
	}
	return g
}

func TestAllowedMatching(t *testing.T) {
	g := mustNew(t, "example.com", "api.example.com:8443", "*.cdn.example.com", "[::1]")
	cases := map[string]bool{
		"example.com":                 true,
		"EXAMPLE.com":                 true,
		"example.com.":                true, // trailing dot
		"example.com:8080":            true, // entry has no port: any port
		"api.example.com:8443":        true,
		"api.example.com:9999":        false, // entry pins the port
		"api.example.com":             false, // ...so a missing port doesn't match
		"x.cdn.example.com":           true,
		"a.b.cdn.example.com":         true,
		"cdn.example.com":             false, // wildcard excludes the apex
		"evilcdn.example.com":         false, // not a label boundary
		"evil.example":                false,
		"example.com.evil.example":    false,
		"evil.example/example.com":    false,
		"":                            false,
		"[::1]":                       true,
		"[::1]:8080":                  true,
		"::1":                         false, // unbracketed IPv6 is malformed
		"203.0.113.9":                 false,
		"example.com@evil.example":    false,
		"user:pw@example.com":         false,
		"example.com:80 evil.example": false,
	}
	for in, want := range cases {
		if got := g.Allowed(in); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNewRejectsBadEntries(t *testing.T) {
	for _, bad := range []string{"", "  ", "https://example.com", "example.com/path", "a*.example.com",
		"*", "*.", "example.com:", "example.com:0", "example.com:99999", "example.com:abc", "::1", "[::1", "user@example.com"} {
		if _, err := New([]string{bad}); err == nil {
			t.Errorf("New(%q): expected an error", bad)
		}
	}
}

func serve(t *testing.T, g *Guard, mutate func(*http.Request)) (*httptest.ResponseRecorder, []events.Event) {
	t.Helper()
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	ch, cancel := logger.Subscribe()
	defer cancel()
	h := g.Middleware(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/forgot", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	mutate(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var got []events.Event
	for {
		select {
		case e := <-ch:
			got = append(got, e)
		default:
			return rec, got
		}
	}
}

func TestMiddleware(t *testing.T) {
	g := mustNew(t, "example.com", "*.example.com")
	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"allowed host", func(r *http.Request) { r.Host = "example.com" }, 200},
		{"allowed host with port", func(r *http.Request) { r.Host = "example.com:8080" }, 200},
		{"evil host", func(r *http.Request) { r.Host = "evil.example" }, 403},
		{"no host", func(r *http.Request) { r.Host = "" }, 403},
		{"bare IP host", func(r *http.Request) { r.Host = "203.0.113.9" }, 403},
		{"evil X-Forwarded-Host", func(r *http.Request) {
			r.Host = "example.com"
			r.Header.Set("X-Forwarded-Host", "evil.example")
		}, 403},
		{"evil second element of X-Forwarded-Host", func(r *http.Request) {
			r.Host = "example.com"
			r.Header.Set("X-Forwarded-Host", "example.com, evil.example")
		}, 403},
		{"allowed X-Forwarded-Host", func(r *http.Request) {
			r.Host = "example.com"
			r.Header.Set("X-Forwarded-Host", "www.example.com")
		}, 200},
		{"evil X-Host", func(r *http.Request) {
			r.Host = "example.com"
			r.Header.Set("X-Host", "evil.example")
		}, 403},
		{"evil Forwarded host=", func(r *http.Request) {
			r.Host = "example.com"
			r.Header.Set("Forwarded", `for=1.2.3.4;host="evil.example";proto=https`)
		}, 403},
		{"allowed Forwarded host=", func(r *http.Request) {
			r.Host = "example.com"
			r.Header.Set("Forwarded", "for=1.2.3.4;host=www.example.com")
		}, 200},
		{"Forwarded without host is ignored", func(r *http.Request) {
			r.Host = "example.com"
			r.Header.Set("Forwarded", "for=1.2.3.4;proto=https")
		}, 200},
		{"evil header on a second header line", func(r *http.Request) {
			r.Host = "example.com"
			r.Header.Add("X-Forwarded-Host", "example.com")
			r.Header.Add("X-Forwarded-Host", "evil.example")
		}, 403},
	}
	for _, c := range cases {
		rec, evs := serve(t, g, c.mutate)
		if rec.Code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, rec.Code, c.want)
		}
		if c.want == 403 {
			if len(evs) != 1 || evs[0].Layer != "hostguard" || evs[0].Action != events.ActionBlock ||
				evs[0].ClientIP != "203.0.113.5" || !strings.Contains(evs[0].Reason, "allowed_hosts") {
				t.Errorf("%s: unexpected events %+v", c.name, evs)
			}
			// the attacker-chosen value must not become part of the reason
			if len(evs) == 1 && strings.Contains(evs[0].Reason, "evil") {
				t.Errorf("%s: reason echoes the request value: %q", c.name, evs[0].Reason)
			}
		} else if len(evs) != 0 {
			t.Errorf("%s: allowed request logged %+v", c.name, evs)
		}
	}
}
