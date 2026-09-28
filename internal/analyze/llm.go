package analyze

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://api.anthropic.com/v1/messages"
	defaultModel   = "claude-sonnet-5"
	anthropicVer   = "2023-06-01"
)

// httpDoer is satisfied by *http.Client; tests substitute an
// httptest.Server-backed client instead of a real API key, the same
// fake-the-boundary pattern Scryer's semgrep package uses with a fake
// binary in place of a real subprocess.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Narrator turns an aggregated Summary into a plain-English report using
// the Anthropic Messages API. It is optional: rampart-analyze runs fine
// without one configured, producing just the deterministic Summary — see
// cmd/rampart-analyze/main.go.
type Narrator struct {
	APIKey     string
	Model      string
	BaseURL    string
	HTTPClient httpDoer
}

// NewNarrator builds a Narrator with sane defaults. apiKey must be
// non-empty; callers decide whether to construct one at all (see
// cmd/rampart-analyze, which skips this step entirely when no key is
// configured rather than erroring).
func NewNarrator(apiKey string) *Narrator {
	return &Narrator{
		APIKey:     apiKey,
		Model:      defaultModel,
		BaseURL:    defaultBaseURL,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
	}
}

type messagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// systemPrompt is the boundary that keeps the narration honest about what
// the data can actually support. See this package's doc comment for why:
// block-only events, no payload, no allowed-traffic record.
const systemPrompt = `You are summarizing operational metadata about HTTP requests a web application firewall (Rampart) already blocked. You are given only aggregated counts: attacker IPs, block reasons per detection layer, targeted paths, IPs that triggered multiple detection layers, and traffic bursts. You do NOT have the actual request payloads, and you have NO record of allowed (non-blocked) traffic.

Because of that:
- Do not claim to identify gaps in detection coverage, missed attacks, or attacks that "got through" — this data cannot show that, since only already-blocked requests are recorded here.
- Do not draft or suggest specific new detection rule syntax (regex, WAF rules) — there is no payload content to base one on.
- Do write a short, plain-English summary of what happened in this window, and where the data supports it, suggest operational follow-ups a human could take (e.g., adding a persistent attacker's IP to a deny-list, tightening a rate limit for a targeted endpoint, reviewing a burst as possibly automated/scripted traffic).

Be concrete and cite the specific numbers you were given. Keep it under 300 words.`

// Narrate calls the Anthropic API with a prompt built from s and returns
// the model's plain-text response.
func (n *Narrator) Narrate(ctx context.Context, s Summary) (string, error) {
	if n.APIKey == "" {
		return "", fmt.Errorf("analyze: no API key configured")
	}

	reqBody := messagesRequest{
		Model:     n.Model,
		MaxTokens: 1024,
		System:    systemPrompt,
		Messages: []message{
			{Role: "user", Content: buildPrompt(s)},
		},
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("analyze: encoding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, n.BaseURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("analyze: building request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", n.APIKey)
	httpReq.Header.Set("anthropic-version", anthropicVer)

	resp, err := n.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("analyze: calling Anthropic API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("analyze: reading response: %w", err)
	}

	var parsed messagesResponse
	if jsonErr := json.Unmarshal(body, &parsed); jsonErr != nil {
		return "", fmt.Errorf("analyze: parsing response (status %d): %w", resp.StatusCode, jsonErr)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("analyze: API error (%s): %s", parsed.Error.Type, parsed.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("analyze: API returned status %d", resp.StatusCode)
	}

	var text strings.Builder
	for _, block := range parsed.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	if text.Len() == 0 {
		return "", fmt.Errorf("analyze: API response had no text content")
	}
	return text.String(), nil
}

// buildPrompt renders a Summary as plain text for the model — the
// aggregated counts only, never raw events (there'd be nothing extra to
// send anyway; events carry no payload).
func buildPrompt(s Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Window: %s to %s\n", s.WindowStart.Format(time.RFC3339), s.WindowEnd.Format(time.RFC3339))
	fmt.Fprintf(&b, "Total blocked requests: %d\n\n", s.TotalEvents)

	b.WriteString("By layer:\n")
	for layer, count := range s.ByLayer {
		fmt.Fprintf(&b, "- %s: %d\n", layer, count)
	}

	b.WriteString("\nTop attacker IPs:\n")
	for _, ip := range s.TopAttackers {
		fmt.Fprintf(&b, "- %s: %d blocked requests\n", ip.IP, ip.Count)
	}

	b.WriteString("\nTop block reasons:\n")
	for _, r := range s.TopReasons {
		fmt.Fprintf(&b, "- [%s] %s: %d\n", r.Layer, r.Reason, r.Count)
	}

	b.WriteString("\nMost-targeted paths:\n")
	for _, p := range s.TopPaths {
		fmt.Fprintf(&b, "- %s: %d\n", p.Path, p.Count)
	}

	if len(s.MultiVector) > 0 {
		b.WriteString("\nIPs that triggered more than one detection layer:\n")
		for _, m := range s.MultiVector {
			fmt.Fprintf(&b, "- %s: layers %v, %d total blocked requests\n", m.IP, m.Layers, m.Count)
		}
	}

	if len(s.Bursts) > 0 {
		b.WriteString("\nTraffic bursts (>= 10 blocked requests from one IP within 5 minutes):\n")
		for _, burst := range s.Bursts {
			fmt.Fprintf(&b, "- %s: %d requests between %s and %s, layers %v\n",
				burst.IP, burst.Count, burst.Start.Format(time.RFC3339), burst.End.Format(time.RFC3339), burst.Layers)
		}
	}

	return b.String()
}
