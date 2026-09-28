package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/singhmarch86/rampart/internal/events"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddlewareNilLimiterPassesThrough(t *testing.T) {
	logger, _ := events.NewLogger("")
	h := Middleware(nil, "test", logger, okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected nil limiter to pass through, got %d", rec.Code)
	}
}

func TestMiddlewareBlocksOverRate(t *testing.T) {
	logger, _ := events.NewLogger("")
	limiter := New(1, 1, 0, time.Minute)
	defer limiter.Close()
	h := Middleware(limiter, "test-layer", logger, okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.2:1234"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second immediate request to be rate limited, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on rate-limited response")
	}
}

func TestMiddlewareBlocksOverConcurrency(t *testing.T) {
	logger, _ := events.NewLogger("")
	limiter := New(1000, 1000, 1, time.Minute)
	defer limiter.Close()

	block := make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(limiter, "test-layer", logger, slow)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.3:1234"

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		done <- rec.Code
	}()

	// Give the first request time to occupy the single concurrency slot.
	time.Sleep(50 * time.Millisecond)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second concurrent request to be blocked, got %d", rec.Code)
	}

	close(block)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("expected first (slow) request to eventually succeed, got %d", code)
	}
}

func TestClientIPParsesRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:54321"
	if got := ClientIP(req); got.String() != "198.51.100.7" {
		t.Fatalf("expected 198.51.100.7, got %s", got)
	}
}

func TestClientIPFallsBackOnMalformedRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-an-address"
	if got := ClientIP(req); got.String() != "0.0.0.0" {
		t.Fatalf("expected zero IP fallback for malformed RemoteAddr, got %s", got)
	}
}
