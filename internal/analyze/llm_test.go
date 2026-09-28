package analyze

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeAnthropicServer stands in for the real Anthropic API the same way
// Scryer's fake-semgrep shell script stands in for a real semgrep binary —
// so these tests exercise the actual HTTP request/response handling
// without needing a real API key or network access.
func fakeAnthropicServer(t *testing.T, status int, respBody string, checkReq func(*testing.T, messagesRequest)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checkReq != nil {
			var req messagesRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decoding request body: %v", err)
			}
			checkReq(t, req)
		}
		if r.Header.Get("x-api-key") == "" {
			t.Error("expected x-api-key header to be set")
		}
		w.WriteHeader(status)
		w.Write([]byte(respBody)) //nolint:errcheck
	}))
}

func TestNarrateReturnsModelText(t *testing.T) {
	srv := fakeAnthropicServer(t, http.StatusOK, `{"content":[{"type":"text","text":"3 attackers, one IP hit two layers."}]}`, func(t *testing.T, req messagesRequest) {
		if req.Model == "" {
			t.Error("expected a model to be set on the request")
		}
		if len(req.Messages) != 1 || !strings.Contains(req.Messages[0].Content, "Total blocked requests: 5") {
			t.Errorf("expected the prompt to include the aggregated summary, got %q", req.Messages[0].Content)
		}
	})
	defer srv.Close()

	n := NewNarrator("test-key")
	n.BaseURL = srv.URL
	n.HTTPClient = srv.Client()

	s := Summary{TotalEvents: 5, ByLayer: map[string]int{"waf": 5}}
	text, err := n.Narrate(context.Background(), s)
	if err != nil {
		t.Fatalf("Narrate: %v", err)
	}
	if text != "3 attackers, one IP hit two layers." {
		t.Errorf("unexpected narration text: %q", text)
	}
}

func TestNarrateSurfacesAPIError(t *testing.T) {
	srv := fakeAnthropicServer(t, http.StatusOK, `{"error":{"type":"invalid_request_error","message":"bad key"}}`, nil)
	defer srv.Close()

	n := NewNarrator("test-key")
	n.BaseURL = srv.URL
	n.HTTPClient = srv.Client()

	_, err := n.Narrate(context.Background(), Summary{TotalEvents: 1, ByLayer: map[string]int{}})
	if err == nil {
		t.Fatal("expected an error when the API returns an error object")
	}
}

func TestNarrateRequiresAPIKey(t *testing.T) {
	n := NewNarrator("")
	_, err := n.Narrate(context.Background(), Summary{})
	if err == nil {
		t.Fatal("expected an error for an empty API key")
	}
}

func TestNarrateRespectsContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":[{"type":"text","text":"too slow"}]}`)) //nolint:errcheck
	}))
	defer srv.Close()

	n := NewNarrator("test-key")
	n.BaseURL = srv.URL
	n.HTTPClient = srv.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := n.Narrate(ctx, Summary{ByLayer: map[string]int{}})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestBuildPromptIncludesAllSections(t *testing.T) {
	s := Summary{
		TotalEvents:  2,
		ByLayer:      map[string]int{"waf": 2},
		TopAttackers: []IPCount{{IP: "1.1.1.1", Count: 2}},
		TopReasons:   []ReasonCount{{Layer: "waf", Reason: "sqli", Count: 2}},
		TopPaths:     []PathCount{{Path: "/search", Count: 2}},
		MultiVector:  []MultiVectorIP{{IP: "1.1.1.1", Layers: []string{"apiabuse", "waf"}, Count: 2}},
	}
	prompt := buildPrompt(s)
	for _, want := range []string{"1.1.1.1", "sqli", "/search", "apiabuse"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("expected prompt to mention %q, got:\n%s", want, prompt)
		}
	}
}
