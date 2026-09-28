package schema

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
)

const loginSchema = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"type": "object",
	"properties": {
		"email": {"type": "string"},
		"password": {"type": "string"}
	},
	"required": ["email", "password"],
	"additionalProperties": false
}`

func newTestValidator(t *testing.T, schemaJSON, pathPrefix string, methods ...string) *Validator {
	t.Helper()
	dir := t.TempDir()
	schemaPath := filepath.Join(dir, "schema.json")
	if err := os.WriteFile(schemaPath, []byte(schemaJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(config.SchemaValidationConfig{
		Enabled: true,
		Rules: []config.SchemaRule{
			{Methods: methods, PathPrefix: pathPrefix, SchemaFile: schemaPath},
		},
	}, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func doRequest(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestValidBodyPasses(t *testing.T) {
	v := newTestValidator(t, loginSchema, "/login", "POST")
	rec := doRequest(v.Middleware(okHandler()), http.MethodPost, "/login", `{"email":"a@b.com","password":"x"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected valid body to pass, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMissingRequiredFieldRejected(t *testing.T) {
	v := newTestValidator(t, loginSchema, "/login", "POST")
	rec := doRequest(v.Middleware(okHandler()), http.MethodPost, "/login", `{"email":"a@b.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected missing required field to be rejected with 400, got %d", rec.Code)
	}
}

func TestUnexpectedFieldRejected(t *testing.T) {
	v := newTestValidator(t, loginSchema, "/login", "POST")
	rec := doRequest(v.Middleware(okHandler()), http.MethodPost, "/login",
		`{"email":"a@b.com","password":"x","isAdmin":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected mass-assignment-style extra field to be rejected with 400, got %d", rec.Code)
	}
}

func TestWrongTypeRejected(t *testing.T) {
	v := newTestValidator(t, loginSchema, "/login", "POST")
	rec := doRequest(v.Middleware(okHandler()), http.MethodPost, "/login", `{"email":123,"password":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected wrong-typed field to be rejected with 400, got %d", rec.Code)
	}
}

func TestMalformedJSONRejected(t *testing.T) {
	v := newTestValidator(t, loginSchema, "/login", "POST")
	rec := doRequest(v.Middleware(okHandler()), http.MethodPost, "/login", `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected malformed JSON to be rejected with 400, got %d", rec.Code)
	}
}

func TestUnrelatedPathNotValidated(t *testing.T) {
	v := newTestValidator(t, loginSchema, "/login", "POST")
	rec := doRequest(v.Middleware(okHandler()), http.MethodPost, "/rest/products", `not even json`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected unrelated path to pass through unvalidated, got %d", rec.Code)
	}
}

func TestBodyIsRestoredForUpstream(t *testing.T) {
	v := newTestValidator(t, loginSchema, "/login", "POST")
	var seenBody string
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		seenBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	body := `{"email":"a@b.com","password":"x"}`
	rec := doRequest(h, http.MethodPost, "/login", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected valid body to pass, got %d", rec.Code)
	}
	if seenBody != body {
		t.Fatalf("expected upstream to see original body %q, got %q", body, seenBody)
	}
}
