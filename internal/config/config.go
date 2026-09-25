// Package config loads and validates Rampart's YAML configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    string                 `yaml:"listen"`
	Upstream  string                 `yaml:"upstream"`
	Firewall  FirewallConfig         `yaml:"firewall"`
	RateLimit RateLimitConfig        `yaml:"rate_limit"`
	WAF       WAFConfig              `yaml:"waf"`
	APIAbuse  APIAbuseConfig         `yaml:"api_abuse"`
	Schema    SchemaValidationConfig `yaml:"schema_validation"`
	Dashboard DashboardConfig        `yaml:"dashboard"`
	Logging   LoggingConfig          `yaml:"logging"`
}

type FirewallConfig struct {
	// Allow, if non-empty, is the only set of CIDRs permitted through; everything else is denied.
	Allow []string `yaml:"allow"`
	// Deny is checked after Allow; any CIDR here is blocked even if Allow is empty (default allow-all).
	Deny []string `yaml:"deny"`
}

type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	// RequestsPerSecond is the sustained rate allowed per client IP.
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	// Burst is the maximum number of requests allowed in a single instant above the sustained rate.
	Burst int `yaml:"burst"`
	// MaxConcurrentPerIP caps simultaneous in-flight requests per client IP (crude flood mitigation
	// at the HTTP layer; real SYN-flood protection belongs in the OS firewall, see docs/NETWORK_HARDENING.md).
	MaxConcurrentPerIP int `yaml:"max_concurrent_per_ip"`
	// IdleTimeout controls how long an IP's rate-limit state is kept after its last request.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

type WAFConfig struct {
	Enabled bool `yaml:"enabled"`
	// Mode is "block" (enforce) or "detect" (log matches but let requests through;
	// useful for tuning a new deployment before enabling enforcement).
	Mode string `yaml:"mode"`
	// CustomRulesDir, if set, loads every *.conf file in the directory (SecLang syntax,
	// same as ModSecurity/CRS) after the OWASP Core Rule Set, sorted by filename.
	CustomRulesDir string `yaml:"custom_rules_dir"`
	// RequestBodyLimit/ResponseBodyLimit cap how many bytes of a request/response body
	// are buffered for inspection, in bytes. Zero uses Coraza's defaults.
	RequestBodyLimit  int `yaml:"request_body_limit"`
	ResponseBodyLimit int `yaml:"response_body_limit"`
}

// APIAbuseConfig detects credential stuffing and token abuse: repeated
// authentication failures from the same IP against a configured endpoint.
// Both use cases share one mechanism (a rule watching for a flood of
// "failure" status codes on a path) because a brute-forced login and a
// brute-forced/guessed token both look the same from the firewall's
// vantage point: the same client racking up 401s.
type APIAbuseConfig struct {
	Enabled bool           `yaml:"enabled"`
	Rules   []APIAbuseRule `yaml:"rules"`
}

type APIAbuseRule struct {
	// Name identifies the rule in logs and config errors.
	Name string `yaml:"name"`
	// Methods this rule applies to. Empty means all methods.
	Methods []string `yaml:"methods"`
	// PathPrefix selects which requests this rule watches.
	PathPrefix string `yaml:"path_prefix"`
	// FailureStatusCodes are the upstream response codes that count as a
	// failed attempt (e.g. 401 for a rejected login or invalid token).
	FailureStatusCodes []int `yaml:"failure_status_codes"`
	// MaxFailures is how many failures from one IP within Window trigger a block.
	MaxFailures int `yaml:"max_failures"`
	// Window is the sliding period failures are counted over.
	Window time.Duration `yaml:"window"`
	// BlockDuration is how long the IP is blocked once MaxFailures is reached.
	BlockDuration time.Duration `yaml:"block_duration"`
}

// SchemaValidationConfig rejects request bodies that don't match an
// expected JSON Schema for a route, before they reach the upstream
// application. This targets malformed/unexpected-field abuse (e.g. mass
// assignment) that pattern-matching WAF rules aren't designed to catch,
// since a well-formed-looking but structurally wrong request isn't an
// attack signature, it's a schema violation.
type SchemaValidationConfig struct {
	Enabled bool         `yaml:"enabled"`
	Rules   []SchemaRule `yaml:"rules"`
}

type SchemaRule struct {
	// Methods this rule applies to. Empty means all methods.
	Methods []string `yaml:"methods"`
	// PathPrefix selects which requests this rule validates.
	PathPrefix string `yaml:"path_prefix"`
	// SchemaFile is a path to a JSON Schema (draft 2020-12/2019-09/07) file.
	SchemaFile string `yaml:"schema_file"`
}

type LoggingConfig struct {
	// EventsPath is where structured JSONL block/allow events are written. Empty disables event logging.
	EventsPath string `yaml:"events_path"`
}

// DashboardConfig serves the live attack-analytics dashboard. It has no
// authentication of its own yet, so it's deliberately a separate listener
// from the public proxy port — see docs/ROADMAP.md.
type DashboardConfig struct {
	Enabled bool `yaml:"enabled"`
	// Listen is the dashboard's own address, separate from the proxy's `listen`.
	Listen string `yaml:"listen"`
}

func Default() Config {
	return Config{
		Listen:   ":8080",
		Upstream: "http://localhost:3000",
		RateLimit: RateLimitConfig{
			Enabled:            true,
			RequestsPerSecond:  10,
			Burst:              20,
			MaxConcurrentPerIP: 50,
			IdleTimeout:        10 * time.Minute,
		},
		WAF: WAFConfig{
			Enabled: true,
			Mode:    "block",
		},
		Dashboard: DashboardConfig{
			Enabled: false,
			Listen:  "127.0.0.1:9090",
		},
		Logging: LoggingConfig{
			EventsPath: "rampart-events.jsonl",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if c.Upstream == "" {
		return fmt.Errorf("upstream must not be empty")
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.RequestsPerSecond <= 0 {
			return fmt.Errorf("rate_limit.requests_per_second must be > 0 when enabled")
		}
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("rate_limit.burst must be > 0 when enabled")
		}
	}
	if c.WAF.Enabled && c.WAF.Mode != "" && c.WAF.Mode != "block" && c.WAF.Mode != "detect" {
		return fmt.Errorf("waf.mode must be \"block\" or \"detect\", got %q", c.WAF.Mode)
	}
	if c.APIAbuse.Enabled {
		for i, r := range c.APIAbuse.Rules {
			if r.PathPrefix == "" {
				return fmt.Errorf("api_abuse.rules[%d]: path_prefix must not be empty", i)
			}
			if len(r.FailureStatusCodes) == 0 {
				return fmt.Errorf("api_abuse.rules[%d] (%s): failure_status_codes must not be empty", i, r.Name)
			}
			if r.MaxFailures <= 0 {
				return fmt.Errorf("api_abuse.rules[%d] (%s): max_failures must be > 0", i, r.Name)
			}
			if r.Window <= 0 {
				return fmt.Errorf("api_abuse.rules[%d] (%s): window must be > 0", i, r.Name)
			}
			if r.BlockDuration <= 0 {
				return fmt.Errorf("api_abuse.rules[%d] (%s): block_duration must be > 0", i, r.Name)
			}
		}
	}
	if c.Schema.Enabled {
		for i, r := range c.Schema.Rules {
			if r.PathPrefix == "" {
				return fmt.Errorf("schema_validation.rules[%d]: path_prefix must not be empty", i)
			}
			if r.SchemaFile == "" {
				return fmt.Errorf("schema_validation.rules[%d]: schema_file must not be empty", i)
			}
		}
	}
	if c.Dashboard.Enabled {
		if c.Dashboard.Listen == "" {
			return fmt.Errorf("dashboard.listen must not be empty when dashboard is enabled")
		}
		if c.Dashboard.Listen == c.Listen {
			return fmt.Errorf("dashboard.listen must differ from listen (the dashboard must not share the public proxy port)")
		}
	}
	return nil
}
