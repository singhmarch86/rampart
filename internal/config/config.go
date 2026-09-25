// Package config loads and validates Rampart's YAML configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    string          `yaml:"listen"`
	Upstream  string          `yaml:"upstream"`
	Firewall  FirewallConfig  `yaml:"firewall"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	WAF       WAFConfig       `yaml:"waf"`
	Logging   LoggingConfig   `yaml:"logging"`
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

type LoggingConfig struct {
	// EventsPath is where structured JSONL block/allow events are written. Empty disables event logging.
	EventsPath string `yaml:"events_path"`
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
	return nil
}
