package analytics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gauravdeepsingh/rampart/internal/events"
)

func TestServerRendersPublicNoticeWhenSet(t *testing.T) {
	logger, _ := events.NewLogger("")
	store := New(logger)
	defer store.Close()

	srv := NewServer(store, "public demo, not a real service")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `class="public-notice"`) {
		t.Errorf("expected a public-notice div in the page, got none")
	}
	if !strings.Contains(body, "public demo, not a real service") {
		t.Errorf("expected the notice text in the page")
	}
	if strings.Contains(body, publicNoticePlaceholder) {
		t.Errorf("expected the placeholder comment to be replaced, found it still present")
	}
}

func TestServerOmitsPublicNoticeWhenUnset(t *testing.T) {
	logger, _ := events.NewLogger("")
	store := New(logger)
	defer store.Close()

	srv := NewServer(store, "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, `class="public-notice"`) {
		t.Errorf("expected no public-notice div when unset, but found one")
	}
	if strings.Contains(body, publicNoticePlaceholder) {
		t.Errorf("expected the placeholder comment to be removed even when empty")
	}
}

func TestServerEscapesNoticeHTML(t *testing.T) {
	logger, _ := events.NewLogger("")
	store := New(logger)
	defer store.Close()

	srv := NewServer(store, `<script>alert(1)</script>`)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("expected notice HTML to be escaped, found raw script tag in output")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected an escaped form of the notice text")
	}
}
