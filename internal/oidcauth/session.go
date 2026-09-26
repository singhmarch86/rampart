package oidcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const sessionCookieName = "rampart_session"

var (
	ErrNoSession      = errors.New("no session cookie")
	ErrInvalidSession = errors.New("invalid session cookie")
	ErrSessionExpired = errors.New("session expired")
)

// Session is what's encoded (signed, not encrypted — don't put secrets in
// here) into the session cookie.
type Session struct {
	Subject string   `json:"sub"`
	Roles   []string `json:"roles"`
	// IDToken is kept only so logout can pass it as id_token_hint to the
	// IdP's end_session_endpoint (RP-Initiated Logout) — it's not used for
	// any authorization decision, Subject/Roles are. Kept empty if the
	// provider doesn't do RP-initiated logout, so nothing sensitive sits
	// in the cookie unnecessarily.
	IDToken string    `json:"idt,omitempty"`
	Expiry  time.Time `json:"exp"`
}

// SessionManager signs and verifies session cookies with HMAC-SHA256. This
// is a stateless design (no server-side session store) — logout works by
// overwriting the cookie, not by invalidating a server-side record, which
// means a stolen, still-valid cookie remains valid until it expires. That
// tradeoff is why SessionDuration should be kept short-ish (default 8h)
// rather than left open-ended.
type SessionManager struct {
	secret   []byte
	duration time.Duration
	secure   bool // false only in tests; real use always sets Secure on the cookie
}

func NewSessionManager(secret string, duration time.Duration) *SessionManager {
	return &SessionManager{secret: []byte(secret), duration: duration, secure: true}
}

func (sm *SessionManager) sign(payload []byte) string {
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write(payload)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (sm *SessionManager) Create(w http.ResponseWriter, subject string, roles []string, rawIDToken string) error {
	sess := Session{Subject: subject, Roles: roles, IDToken: rawIDToken, Expiry: time.Now().Add(sm.duration)}
	payload, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sm.sign(payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.Expiry,
	})
	return nil
}

func (sm *SessionManager) Verify(r *http.Request) (*Session, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, ErrNoSession
	}
	sess, err := sm.parse(c.Value)
	if err != nil {
		return nil, err
	}
	if time.Now().After(sess.Expiry) {
		return nil, ErrSessionExpired
	}
	return sess, nil
}

func (sm *SessionManager) parse(cookieValue string) (*Session, error) {
	dot := -1
	for i := len(cookieValue) - 1; i >= 0; i-- {
		if cookieValue[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, ErrInvalidSession
	}
	payloadB64, sigB64 := cookieValue[:dot], cookieValue[dot+1:]

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrInvalidSession
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, ErrInvalidSession
	}

	mac := hmac.New(sha256.New, sm.secret)
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) || subtle.ConstantTimeCompare(sig, expected) != 1 {
		return nil, ErrInvalidSession
	}

	var sess Session
	if err := json.Unmarshal(payload, &sess); err != nil {
		return nil, ErrInvalidSession
	}
	return &sess, nil
}

func (sm *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}
