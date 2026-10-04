package realip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func resolved(t *testing.T, trusted []string, remoteAddr string, xff ...string) string {
	t.Helper()
	rs, err := New(trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var got string
	h := rs.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.RemoteAddr
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestNoTrustedProxiesIsNoOp(t *testing.T) {
	got := resolved(t, nil, "10.0.0.1:1111", "203.0.113.9")
	if got != "10.0.0.1:1111" {
		t.Fatalf("expected RemoteAddr untouched with no trusted proxies, got %q", got)
	}
}

func TestTrustedProxyHeaderIsHonored(t *testing.T) {
	got := resolved(t, []string{"10.0.0.0/8"}, "10.0.0.1:1111", "203.0.113.9")
	if got != "203.0.113.9:1111" {
		t.Fatalf("expected client IP from XFF with peer's port, got %q", got)
	}
}

// The reason this is an allowlist: a client connecting directly must not be
// able to pick its own IP by sending the header.
func TestUntrustedPeerCannotSpoofHeader(t *testing.T) {
	got := resolved(t, []string{"10.0.0.0/8"}, "198.51.100.7:2222", "203.0.113.9")
	if got != "198.51.100.7:2222" {
		t.Fatalf("expected untrusted peer's header to be ignored, got %q", got)
	}
}

// A client can prepend fake entries; only the rightmost untrusted hop,
// the one the trusted proxy actually saw, counts.
func TestSpoofedLeftmostEntryIgnored(t *testing.T) {
	got := resolved(t, []string{"10.0.0.0/8"}, "10.0.0.1:1111", "1.2.3.4, 203.0.113.9")
	if got != "203.0.113.9:1111" {
		t.Fatalf("expected rightmost untrusted hop, got %q", got)
	}
}

func TestMultipleTrustedHopsSkipped(t *testing.T) {
	got := resolved(t, []string{"10.0.0.0/8"}, "10.0.0.1:1111", "203.0.113.9, 10.0.0.5")
	if got != "203.0.113.9:1111" {
		t.Fatalf("expected trusted hops skipped, got %q", got)
	}
}

func TestAllHopsTrustedUsesLeftmost(t *testing.T) {
	got := resolved(t, []string{"10.0.0.0/8"}, "10.0.0.1:1111", "10.1.1.1, 10.0.0.5")
	if got != "10.1.1.1:1111" {
		t.Fatalf("expected leftmost when every hop is trusted, got %q", got)
	}
}

func TestMalformedHeaderLeavesRemoteAddr(t *testing.T) {
	got := resolved(t, []string{"10.0.0.0/8"}, "10.0.0.1:1111", "not-an-ip")
	if got != "10.0.0.1:1111" {
		t.Fatalf("expected RemoteAddr untouched on malformed header, got %q", got)
	}
}

func TestMissingHeaderLeavesRemoteAddr(t *testing.T) {
	got := resolved(t, []string{"10.0.0.0/8"}, "10.0.0.1:1111")
	if got != "10.0.0.1:1111" {
		t.Fatalf("expected RemoteAddr untouched without header, got %q", got)
	}
}

func TestMultipleHeaderLinesAndIPv6(t *testing.T) {
	got := resolved(t, []string{"10.0.0.0/8"}, "10.0.0.1:1111", "9.9.9.9", "2001:db8::1")
	if got != "[2001:db8::1]:1111" {
		t.Fatalf("expected IPv6 client from the last header line, got %q", got)
	}
}

func TestBareIPTrustedProxy(t *testing.T) {
	got := resolved(t, []string{"10.0.0.1"}, "10.0.0.1:1111", "203.0.113.9")
	if got != "203.0.113.9:1111" {
		t.Fatalf("expected bare IP entry to work as /32, got %q", got)
	}
}

func TestInvalidTrustedProxyRejected(t *testing.T) {
	if _, err := New([]string{"nonsense"}); err == nil {
		t.Fatal("expected error for invalid trusted proxy entry")
	}
}
