package oidcauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	sm := NewSessionManager("test-secret-at-least-32-bytes-long", time.Hour)

	rec := httptest.NewRecorder()
	if err := sm.Create(rec, "alice", []string{"admin"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	sess, err := sm.Verify(req)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sess.Subject != "alice" {
		t.Fatalf("expected subject alice, got %s", sess.Subject)
	}
	if len(sess.Roles) != 1 || sess.Roles[0] != "admin" {
		t.Fatalf("expected roles [admin], got %v", sess.Roles)
	}
}

func TestSessionNoCookie(t *testing.T) {
	sm := NewSessionManager("test-secret-at-least-32-bytes-long", time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.Verify(req); err != ErrNoSession {
		t.Fatalf("expected ErrNoSession, got %v", err)
	}
}

func TestSessionTamperedPayloadRejected(t *testing.T) {
	sm := NewSessionManager("test-secret-at-least-32-bytes-long", time.Hour)
	rec := httptest.NewRecorder()
	_ = sm.Create(rec, "alice", []string{"viewer"})
	cookie := rec.Result().Cookies()[0]

	// Tamper: swap the first base64url character for a different valid
	// one, keeping the cookie well-formed so this tests signature
	// rejection specifically, not "malformed cookie" rejection.
	tampered := cookie.Value
	swapChar := byte('A')
	if tampered[0] == 'A' {
		swapChar = 'B'
	}
	tampered = string(swapChar) + tampered[1:]

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tampered})
	if _, err := sm.Verify(req); err != ErrInvalidSession {
		t.Fatalf("expected ErrInvalidSession for tampered cookie, got %v", err)
	}
}

func TestSessionWrongSecretRejected(t *testing.T) {
	sm1 := NewSessionManager("secret-one-at-least-32-bytes-long!!", time.Hour)
	sm2 := NewSessionManager("secret-two-at-least-32-bytes-long!!", time.Hour)

	rec := httptest.NewRecorder()
	_ = sm1.Create(rec, "alice", nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	if _, err := sm2.Verify(req); err != ErrInvalidSession {
		t.Fatalf("expected ErrInvalidSession when verifying with a different secret, got %v", err)
	}
}

func TestSessionExpired(t *testing.T) {
	sm := NewSessionManager("test-secret-at-least-32-bytes-long", -time.Hour) // already expired
	rec := httptest.NewRecorder()
	_ = sm.Create(rec, "alice", nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if _, err := sm.Verify(req); err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestSessionClearOverwritesWithExpiredCookie(t *testing.T) {
	sm := NewSessionManager("test-secret-at-least-32-bytes-long", time.Hour)
	rec := httptest.NewRecorder()
	sm.Clear(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].MaxAge >= 0 {
		t.Fatalf("expected negative MaxAge to delete the cookie, got %d", cookies[0].MaxAge)
	}
}
