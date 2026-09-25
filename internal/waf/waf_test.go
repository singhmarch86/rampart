package waf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/gauravdeepsingh/rampart/internal/config"
	"github.com/gauravdeepsingh/rampart/internal/events"
)

func newTestWAF(t *testing.T, cfg config.WAFConfig) *WAF {
	t.Helper()
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatalf("events.NewLogger: %v", err)
	}
	w, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("waf.New: %v", err)
	}
	return w
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func doRequest(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAllowsCleanRequest(t *testing.T) {
	w := newTestWAF(t, config.WAFConfig{Enabled: true, Mode: "block"})
	rec := doRequest(t, w.Middleware(okHandler()), http.MethodGet, "/rest/products/search?q=apple")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected clean request to pass, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestBlocksSQLInjection(t *testing.T) {
	w := newTestWAF(t, config.WAFConfig{Enabled: true, Mode: "block"})
	target := "/rest/products/search?q=" + url.QueryEscape(`' OR '1'='1`)
	rec := doRequest(t, w.Middleware(okHandler()), http.MethodGet, target)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected SQLi payload to be blocked with 403, got %d", rec.Code)
	}
}

func TestBlocksXSS(t *testing.T) {
	w := newTestWAF(t, config.WAFConfig{Enabled: true, Mode: "block"})
	target := "/rest/products/search?q=" + url.QueryEscape("<script>alert(1)</script>")
	rec := doRequest(t, w.Middleware(okHandler()), http.MethodGet, target)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected XSS payload to be blocked with 403, got %d", rec.Code)
	}
}

func TestDetectModeDoesNotBlock(t *testing.T) {
	w := newTestWAF(t, config.WAFConfig{Enabled: true, Mode: "detect"})
	target := "/rest/products/search?q=" + url.QueryEscape(`' OR '1'='1`)
	rec := doRequest(t, w.Middleware(okHandler()), http.MethodGet, target)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected detect mode to let the attack payload through, got %d", rec.Code)
	}
}

func TestCustomRuleBlocks(t *testing.T) {
	dir := t.TempDir()
	rule := `SecRule REQUEST_URI "@beginsWith /internal-admin/" "id:1000001,phase:1,deny,status:404,log,msg:'blocked internal path'"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "01-test.conf"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}

	w := newTestWAF(t, config.WAFConfig{Enabled: true, Mode: "block", CustomRulesDir: dir})

	rec := doRequest(t, w.Middleware(okHandler()), http.MethodGet, "/internal-admin/secrets")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected custom rule to block with 404, got %d", rec.Code)
	}

	rec = doRequest(t, w.Middleware(okHandler()), http.MethodGet, "/public/ok")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected unrelated path to pass, got %d", rec.Code)
	}
}
