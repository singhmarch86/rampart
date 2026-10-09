// Package waf integrates Coraza (a Go implementation of the ModSecurity
// SecLang rule engine) plus the OWASP Core Rule Set to detect and block
// OWASP Top 10 attacks (SQLi, XSS, RCE, path traversal, etc.) at the
// application layer. Detection logic itself is not reimplemented here —
// CRS is a battle-tested, community-maintained rule set; this package's job
// is wiring it into Rampart's request/response pipeline and event log.
//
// Custom, deployment-specific rules are supported by dropping .conf files
// (standard SecLang syntax) into the directory configured as
// waf.custom_rules_dir — they're appended after the CRS include so they can
// see CRS's transformed variables.
package waf

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
)

const (
	defaultRequestBodyLimit  = 10 * 1024 * 1024 // 10MB
	defaultResponseBodyLimit = 5 * 1024 * 1024  // 5MB
)

type WAF struct {
	engine coraza.WAF
	logger *events.Logger
	// detectOnly mirrors mode "detect": matches are logged but not blocked.
	detectOnly bool
}

// XXE detection lives here, not in a SecLang rule, because the rule language
// can't see what it needs: for an XML request body Coraza's XML processor
// exposes only the parsed text values (XML:/*), and REQUEST_BODY and
// REQUEST_BODY_LENGTH are empty. An external entity declaration sits in the
// DOCTYPE, outside those values, so no rule can match it (verified with a
// rule on each variable; see docs/FINDINGS.md #15). The middleware already
// holds the raw bytes, so it checks them directly.
//
// Blocks a body that declares an external general or parameter entity
// (`<!ENTITY n SYSTEM ...>`, `<!ENTITY n PUBLIC ...>`, `<!ENTITY % n ...>`).
// An ordinary `<!DOCTYPE html PUBLIC ...>` declares no entity and does not
// match. Not matched: an internal entity (`<!ENTITY a "text">`) and XML in an
// encoding the WAF doesn't decode (e.g. UTF-16). The real defense is turning
// off external entities in the application's XML parser.
var (
	xmlContentType = regexp.MustCompile(`(?i)^(?:application|text)/(?:[a-z0-9.+-]+\+)?xml`)
	xxeDeclaration = regexp.MustCompile(`(?i)<!ENTITY\s+(?:%\s+)?[^\s>]+\s+(?:SYSTEM|PUBLIC)\b`)
)

// New builds a WAF from cfg. It always loads the Coraza-recommended base
// config and the OWASP Core Rule Set; cfg.Mode controls whether matches are
// actually blocked ("block") or only logged ("detect", useful for tuning a
// new deployment before turning enforcement on).
func New(cfg config.WAFConfig, logger *events.Logger) (*WAF, error) {
	engineMode := "On"
	if cfg.Mode == "detect" {
		engineMode = "DetectionOnly"
	}

	reqLimit := cfg.RequestBodyLimit
	if reqLimit <= 0 {
		reqLimit = defaultRequestBodyLimit
	}
	respLimit := cfg.ResponseBodyLimit
	if respLimit <= 0 {
		respLimit = defaultResponseBodyLimit
	}

	var directives strings.Builder
	directives.WriteString("Include @coraza.conf-recommended\n")
	directives.WriteString("Include @crs-setup.conf.example\n")
	// Must come before the CRS rule files: CRS's initialization rule only
	// defaults the paranoia level to 1 when it is still unset, so this is the
	// equivalent of uncommenting the setting in crs-setup.conf. Setting the
	// blocking level also sets the detection level (CRS defaults it to match).
	// Zero means unset: leave CRS's own default (1) alone.
	if cfg.ParanoiaLevel > 0 {
		fmt.Fprintf(&directives,
			"SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d\"\n",
			cfg.ParanoiaLevel)
	}
	directives.WriteString("Include @owasp_crs/*.conf\n")
	fmt.Fprintf(&directives, "SecRuleEngine %s\n", engineMode)
	directives.WriteString("SecRequestBodyAccess On\n")
	directives.WriteString("SecResponseBodyAccess On\n")
	directives.WriteString("SecResponseBodyMimeType text/plain text/html text/xml application/json\n")

	if cfg.CustomRulesDir != "" {
		custom, err := loadCustomRules(cfg.CustomRulesDir)
		if err != nil {
			return nil, fmt.Errorf("loading custom WAF rules: %w", err)
		}
		directives.WriteString(custom)
	}

	wafConfig := coraza.NewWAFConfig().
		WithDirectives(directives.String()).
		WithRootFS(coreruleset.FS).
		WithRequestBodyAccess().
		WithRequestBodyLimit(reqLimit).
		WithResponseBodyAccess().
		WithResponseBodyLimit(respLimit)

	engine, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("initializing Coraza WAF: %w", err)
	}

	return &WAF{engine: engine, logger: logger, detectOnly: cfg.Mode == "detect"}, nil
}

// loadCustomRules concatenates every *.conf file in dir, sorted by filename
// so ordering is deterministic and configurable (e.g. 01-foo.conf, 02-bar.conf).
func loadCustomRules(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var sb strings.Builder
	for _, name := range names {
		// #nosec G304 -- name comes from os.ReadDir(dir) above, an operator-
		// controlled rules directory from the config file, not from a
		// request; not attacker-reachable.
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", name, err)
		}
		sb.Write(data)
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

// Middleware wraps next with request- and response-phase WAF inspection.
// The response is buffered in memory so Coraza can run response-body rules
// (e.g. information-disclosure detection) before anything reaches the
// client; this trades some memory/latency for that capability, which is
// documented as a known limitation for very large or streamed responses.
func (w *WAF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		tx := w.engine.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			_ = tx.Close()
		}()

		host, portStr, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		port, _ := strconv.Atoi(portStr)
		tx.ProcessConnection(host, port, "", 0)
		tx.SetServerName(r.Host)
		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
		for name, values := range r.Header {
			for _, v := range values {
				tx.AddRequestHeader(name, v)
			}
		}
		if r.Host != "" {
			tx.AddRequestHeader("Host", r.Host)
		}

		if it := tx.ProcessRequestHeaders(); it != nil {
			w.block(rw, r, tx, it)
			return
		}

		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, err = io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				http.Error(rw, "bad request", http.StatusBadRequest)
				return
			}
		}
		if len(bodyBytes) > 0 && xmlContentType.MatchString(r.Header.Get("Content-Type")) &&
			xxeDeclaration.Match(bodyBytes) {
			if w.blockXXE(rw, r) {
				return
			}
		}
		if len(bodyBytes) > 0 {
			if it, _, err := tx.WriteRequestBody(bodyBytes); err != nil {
				http.Error(rw, "bad request", http.StatusBadRequest)
				return
			} else if it != nil {
				w.block(rw, r, tx, it)
				return
			}
		}
		if it, err := tx.ProcessRequestBody(); err != nil {
			http.Error(rw, "bad request", http.StatusBadRequest)
			return
		} else if it != nil {
			w.block(rw, r, tx, it)
			return
		}
		w.recordWouldBlock(r, tx, "Inbound Anomaly Score Exceeded")

		// Restore the body so the reverse proxy can still forward it upstream.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))

		rec := newRecorder()
		next.ServeHTTP(rec, r)

		for name, values := range rec.Header() {
			for _, v := range values {
				tx.AddResponseHeader(name, v)
			}
		}
		if it := tx.ProcessResponseHeaders(rec.status, r.Proto); it != nil {
			w.block(rw, r, tx, it)
			return
		}
		if rec.body.Len() > 0 {
			if it, _, err := tx.WriteResponseBody(rec.body.Bytes()); err != nil {
				http.Error(rw, "bad gateway", http.StatusBadGateway)
				return
			} else if it != nil {
				w.block(rw, r, tx, it)
				return
			}
		}
		if it, err := tx.ProcessResponseBody(); err != nil {
			http.Error(rw, "bad gateway", http.StatusBadGateway)
			return
		} else if it != nil {
			w.block(rw, r, tx, it)
			return
		}
		w.recordWouldBlock(r, tx, "Outbound Anomaly Score Exceeded")

		for k, vv := range rec.Header() {
			for _, v := range vv {
				rw.Header().Add(k, v)
			}
		}
		rw.WriteHeader(rec.status)
		_, _ = rw.Write(rec.body.Bytes())
	})
}

// logEvent writes one WAF event for r.
func (w *WAF) logEvent(r *http.Request, action events.Action, reason string) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	w.logger.Log(events.Event{
		Action: action, Layer: "waf", Reason: reason,
		ClientIP: ip, Method: r.Method, Path: r.URL.Path,
	})
}

// logMatched writes a WAF event carrying the score and contributing rules
// from tx, so the log says why and not just "score exceeded".
func (w *WAF) logMatched(r *http.Request, tx types.Transaction, action events.Action, reason string) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	score, rules, omitted := matchedDetail(tx.MatchedRules())
	w.logger.Log(events.Event{
		Action: action, Layer: "waf", Reason: reason,
		ClientIP: ip, Method: r.Method, Path: r.URL.Path,
		Score: score, Rules: rules, RulesOmitted: omitted,
	})
}

// blockXXE rejects a request whose XML body declares an external entity,
// logging it like any other WAF block. In detect mode it records a
// would-block (detect) event and returns false so the request continues. It
// reports whether it responded.
func (w *WAF) blockXXE(rw http.ResponseWriter, r *http.Request) bool {
	const reason = "Request body declares an external XML entity (XXE)"
	if w.detectOnly {
		w.logEvent(r, events.ActionDetect, reason)
		return false
	}
	w.logEvent(r, events.ActionBlock, reason)
	http.Error(rw, "forbidden", http.StatusForbidden)
	return true
}

// recordWouldBlock is how detect mode reports. In detect mode Coraza never
// interrupts a request, so block() never runs and nothing was logged at all
// (docs/FINDINGS.md #16). Coraza does still record the match: when the
// anomaly score crosses the threshold, the "Inbound/Outbound Anomaly Score
// Exceeded" evaluation rule appears in the transaction's matched rules,
// flagged non-disruptive. If it's there, log one detect event for it. A
// no-op outside detect mode, so block mode is unchanged.
func (w *WAF) recordWouldBlock(r *http.Request, tx types.Transaction, evalMessagePrefix string) {
	if !w.detectOnly {
		return
	}
	for _, mr := range tx.MatchedRules() {
		if msg := mr.Message(); strings.HasPrefix(msg, evalMessagePrefix) {
			w.logMatched(r, tx, events.ActionDetect, msg)
			return
		}
	}
}

func (w *WAF) block(rw http.ResponseWriter, r *http.Request, tx types.Transaction, it *types.Interruption) {
	status := it.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	reason := fmt.Sprintf("rule id %d, action %s", it.RuleID, it.Action)
	if rules := tx.MatchedRules(); len(rules) > 0 {
		last := rules[len(rules)-1]
		if msg := last.Message(); msg != "" {
			reason = msg
		}
	}
	w.logMatched(r, tx, events.ActionBlock, reason)
	http.Error(rw, "forbidden", status)
}

// recorder buffers a response so Coraza can inspect it before it reaches
// the real client.
type recorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newRecorder() *recorder {
	return &recorder{header: make(http.Header), status: http.StatusOK}
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(status int)      { r.status = status }
