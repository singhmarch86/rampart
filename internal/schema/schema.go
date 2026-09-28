// Package schema rejects request bodies that don't match an expected JSON
// Schema for a route, before they reach the upstream application. This
// targets a different failure mode than the WAF: a request can be
// well-formed JSON with no attack signature in it at all, and still be
// wrong — an unexpected field (mass assignment), a string where a number
// was expected, a missing required field — things a signature-based WAF
// isn't designed to catch because there's no "attack pattern" to match.
//
// Scope: REST JSON bodies only. GraphQL's single-endpoint, query-in-body
// shape needs its own query-structure validation, which is different and
// isn't implemented here yet.
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/singhmarch86/rampart/internal/config"
	"github.com/singhmarch86/rampart/internal/events"
)

type compiledRule struct {
	methods    map[string]bool // nil means "all methods"
	pathPrefix string
	schema     *jsonschema.Schema
	schemaFile string
}

type Validator struct {
	rules  []compiledRule
	logger *events.Logger
}

func New(cfg config.SchemaValidationConfig, logger *events.Logger) (*Validator, error) {
	v := &Validator{logger: logger}
	compiler := jsonschema.NewCompiler()

	for _, r := range cfg.Rules {
		sch, err := compiler.Compile(r.SchemaFile)
		if err != nil {
			return nil, fmt.Errorf("compiling schema %s: %w", r.SchemaFile, err)
		}
		cr := compiledRule{pathPrefix: r.PathPrefix, schema: sch, schemaFile: r.SchemaFile}
		if len(r.Methods) > 0 {
			cr.methods = make(map[string]bool, len(r.Methods))
			for _, m := range r.Methods {
				cr.methods[strings.ToUpper(m)] = true
			}
		}
		v.rules = append(v.rules, cr)
	}
	return v, nil
}

func (v *Validator) Middleware(next http.Handler) http.Handler {
	if len(v.rules) == 0 {
		return next
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rule := v.match(r)
		if rule == nil {
			next.ServeHTTP(rw, r)
			return
		}

		var bodyBytes []byte
		if r.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(r.Body)
			_ = r.Body.Close()
			if err != nil {
				http.Error(rw, "bad request", http.StatusBadRequest)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		var doc any
		if err := json.Unmarshal(bodyBytes, &doc); err != nil {
			v.reject(rw, r, rule.schemaFile, "request body is not valid JSON: "+err.Error())
			return
		}
		if err := rule.schema.Validate(doc); err != nil {
			v.reject(rw, r, rule.schemaFile, err.Error())
			return
		}

		next.ServeHTTP(rw, r)
	})
}

func (v *Validator) match(r *http.Request) *compiledRule {
	for i, rule := range v.rules {
		if rule.methods != nil && !rule.methods[strings.ToUpper(r.Method)] {
			continue
		}
		if strings.HasPrefix(r.URL.Path, rule.pathPrefix) {
			return &v.rules[i]
		}
	}
	return nil
}

func (v *Validator) reject(rw http.ResponseWriter, r *http.Request, schemaFile, reason string) {
	v.logger.Log(events.Event{
		Action: events.ActionBlock, Layer: "schema", Reason: fmt.Sprintf("%s: %s", schemaFile, reason),
		ClientIP: clientIP(r), Method: r.Method, Path: r.URL.Path,
	})
	http.Error(rw, "request body does not match the expected schema", http.StatusBadRequest)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
