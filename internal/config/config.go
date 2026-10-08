// Package config loads and validates Rampart's YAML configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/singhmarch86/rampart/internal/ipfilter"
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
	OIDC      OIDCConfig             `yaml:"oidc"`
	Logging   LoggingConfig          `yaml:"logging"`
	TLS       TLSConfig              `yaml:"tls"`
	Server    ServerConfig           `yaml:"server"`
	// TrustedProxies lists CIDRs/IPs of load balancers, Ingress controllers
	// or CDNs directly in front of Rampart. Only connections from these
	// peers have X-Forwarded-For honored when identifying the client; leave
	// empty if clients connect to Rampart directly. See internal/realip.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// ServerConfig bounds how long a client may hold a connection, for both the
// proxy and dashboard listeners. There is deliberately no write timeout:
// it would cut off slow-but-legitimate upstream responses and the
// dashboard's live event stream, since Go applies it to the whole response.
type ServerConfig struct {
	// ReadTimeout is the max time to read an entire request including its
	// body, so a client that sends headers then drips the body (slowloris)
	// is cut off. It does not limit how long a response takes. 0 disables.
	ReadTimeout time.Duration `yaml:"read_timeout"`
	// IdleTimeout is how long an idle keep-alive connection is held open
	// between requests. 0 disables (Go then falls back to ReadTimeout).
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

// TLSConfig terminates TLS directly on Rampart's listeners (the main
// proxy, and the dashboard if enabled) using operator-provided
// certificate/key files - no ACME/auto-cert support, deliberately: that's
// a meaningfully bigger feature (challenge handling, renewal, storage)
// scoped out for now. Bring your own cert, from Let's Encrypt or
// otherwise.
type TLSConfig struct {
	Enabled bool `yaml:"enabled"`
	// CertFile and KeyFile are PEM-encoded, passed straight to
	// http.Server.ListenAndServeTLS.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
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
	// ParanoiaLevel is the OWASP CRS paranoia level, 1-4 (default 1). Higher
	// levels run more CRS rules and catch more, at the cost of more false
	// positives; many rules (e.g. several template-injection and command-
	// injection rules) only exist at level 2 and above. Changing it affects
	// what traffic is blocked, so try it with mode "detect" first.
	ParanoiaLevel int `yaml:"paranoia_level"`
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

// DashboardConfig serves the live attack-analytics dashboard. Without
// oidc.dashboard_auth it has no authentication of its own, so it's
// deliberately a separate listener from the public proxy port — see
// docs/ROADMAP.md.
type DashboardConfig struct {
	Enabled bool `yaml:"enabled"`
	// Listen is the dashboard's own address, separate from the proxy's `listen`.
	Listen string `yaml:"listen"`
	// RateLimit protects the dashboard's own port (login/callback endpoints,
	// the SSE stream) - found missing entirely during a hardening pass, since
	// the dashboard server was never wired through the same rate-limit
	// middleware the main proxy chain gets. See finding #7 in docs/FINDINGS.md.
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	// PublicNotice, if set, renders as a banner at the top of the dashboard
	// page. Meant for a publicly-reachable demo deployment (see
	// docs/PUBLIC_DEMO.md) to state plainly what's being shown and to whom
	// — e.g. "public demo, protecting a deliberately vulnerable practice
	// app, not a real service." Empty (the default) renders no banner.
	PublicNotice string `yaml:"public_notice"`
}

// OIDCConfig makes Rampart an OIDC *relying party / resource server* against
// an existing identity provider (Keycloak, Auth0, Okta, ...). It does not
// make Rampart an identity provider itself — user storage, login UI, and
// token issuance stay with whatever IssuerURL points at. Two independent
// things share this config: dashboard login (DashboardAuth) and
// role-based enforcement on proxied requests (APIRBAC).
type OIDCConfig struct {
	Enabled bool `yaml:"enabled"`
	// IssuerURL is the OIDC provider's issuer, e.g.
	// "https://keycloak.example.com/realms/myrealm". Used for discovery
	// (.well-known/openid-configuration) and JWKS.
	IssuerURL string `yaml:"issuer_url"`
	// RolesClaim is a dot-path into the token's claims where a []string of
	// role names lives. Keycloak's realm roles live at "realm_access.roles"
	// (the default); adjust for other providers (e.g. a custom namespaced
	// claim for Auth0, or "groups" for many providers using group-based auth).
	RolesClaim string `yaml:"roles_claim"`

	DashboardAuth DashboardAuthConfig `yaml:"dashboard_auth"`
	APIRBAC       APIRBACConfig       `yaml:"api_rbac"`
}

// DashboardAuthConfig requires an OIDC login (Authorization Code + PKCE) to
// view the dashboard, closing the "no authentication" gap noted since
// Phase 4. Session state is a signed cookie, not server-side storage.
type DashboardAuthConfig struct {
	Enabled      bool   `yaml:"enabled"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// RedirectURL must exactly match a redirect URI registered with the
	// OIDC client, e.g. "http://localhost:9090/auth/callback".
	RedirectURL string   `yaml:"redirect_url"`
	Scopes      []string `yaml:"scopes"`
	// RequiredRoles: a logged-in user needs at least one of these roles to
	// reach the dashboard. Empty means any authenticated user may in.
	RequiredRoles []string `yaml:"required_roles"`
	// SessionSecret signs the session cookie (HMAC-SHA256). Required —
	// there is no insecure default. Generate with e.g. `openssl rand -hex 32`.
	SessionSecret string `yaml:"session_secret"`
	// SessionDuration caps how long a session is valid without re-login,
	// independent of the OIDC token's own expiry.
	SessionDuration time.Duration `yaml:"session_duration"`
	// PostLogoutRedirectURL is where the IdP sends the browser back after
	// RP-initiated logout (must be registered as a valid post-logout
	// redirect URI on the OIDC client for providers that enforce that,
	// Keycloak included). If empty, or if the provider doesn't advertise
	// an end_session_endpoint, logout only clears Rampart's own session
	// cookie — the IdP session may remain active. See docs/OIDC.md.
	PostLogoutRedirectURL string `yaml:"post_logout_redirect_url"`
}

// APIRBACConfig validates OIDC access tokens on proxied requests and
// enforces per-route role requirements before forwarding upstream — the
// same pattern API gateways (Kong's OIDC plugin, Envoy's JWT filter) use.
type APIRBACConfig struct {
	Enabled bool          `yaml:"enabled"`
	Rules   []APIRBACRule `yaml:"rules"`
}

type APIRBACRule struct {
	// Methods this rule applies to. Empty means all methods.
	Methods []string `yaml:"methods"`
	// PathPrefix selects which requests this rule guards.
	PathPrefix string `yaml:"path_prefix"`
	// Audience, if set, must appear in the token's `aud` claim. Leave empty
	// to skip the audience check (common for Keycloak access tokens, whose
	// audience often isn't the calling client).
	Audience string `yaml:"audience"`
	// RequiredRoles: the token needs at least one of these roles. Empty
	// means any validly-signed, unexpired token is sufficient — no
	// specific role required, just "must be authenticated".
	RequiredRoles []string `yaml:"required_roles"`
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
			Enabled:       true,
			Mode:          "block",
			ParanoiaLevel: 1,
		},
		Dashboard: DashboardConfig{
			Enabled: false,
			Listen:  "127.0.0.1:9090",
			RateLimit: RateLimitConfig{
				Enabled:            true,
				RequestsPerSecond:  5,
				Burst:              10,
				MaxConcurrentPerIP: 10,
				IdleTimeout:        10 * time.Minute,
			},
		},
		OIDC: OIDCConfig{
			RolesClaim: "realm_access.roles",
			DashboardAuth: DashboardAuthConfig{
				Scopes:          []string{"openid", "profile"},
				SessionDuration: 8 * time.Hour,
			},
		},
		Logging: LoggingConfig{
			EventsPath: "rampart-events.jsonl",
		},
		Server: ServerConfig{
			ReadTimeout: 60 * time.Second,
			IdleTimeout: 120 * time.Second,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()

	// #nosec G304 -- path is the -config CLI flag the operator passes at
	// startup, not from a request.
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
	if c.WAF.Enabled && (c.WAF.ParanoiaLevel < 1 || c.WAF.ParanoiaLevel > 4) {
		return fmt.Errorf("waf.paranoia_level must be between 1 and 4, got %d", c.WAF.ParanoiaLevel)
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
		if c.Dashboard.RateLimit.Enabled {
			if c.Dashboard.RateLimit.RequestsPerSecond <= 0 {
				return fmt.Errorf("dashboard.rate_limit.requests_per_second must be > 0 when enabled")
			}
			if c.Dashboard.RateLimit.Burst <= 0 {
				return fmt.Errorf("dashboard.rate_limit.burst must be > 0 when enabled")
			}
		}
	}
	if c.OIDC.Enabled {
		if c.OIDC.IssuerURL == "" {
			return fmt.Errorf("oidc.issuer_url must not be empty when oidc is enabled")
		}
		if c.OIDC.RolesClaim == "" {
			return fmt.Errorf("oidc.roles_claim must not be empty when oidc is enabled")
		}
		if c.OIDC.DashboardAuth.Enabled {
			if !c.Dashboard.Enabled {
				return fmt.Errorf("oidc.dashboard_auth.enabled requires dashboard.enabled")
			}
			if c.OIDC.DashboardAuth.ClientID == "" {
				return fmt.Errorf("oidc.dashboard_auth.client_id must not be empty when enabled")
			}
			if c.OIDC.DashboardAuth.RedirectURL == "" {
				return fmt.Errorf("oidc.dashboard_auth.redirect_url must not be empty when enabled")
			}
			if len(c.OIDC.DashboardAuth.SessionSecret) < 32 {
				return fmt.Errorf("oidc.dashboard_auth.session_secret must be set and at least 32 bytes (e.g. `openssl rand -hex 32`) — there is no insecure default")
			}
			if c.OIDC.DashboardAuth.SessionDuration <= 0 {
				return fmt.Errorf("oidc.dashboard_auth.session_duration must be > 0")
			}
		}
		if c.OIDC.APIRBAC.Enabled {
			for i, r := range c.OIDC.APIRBAC.Rules {
				if r.PathPrefix == "" {
					return fmt.Errorf("oidc.api_rbac.rules[%d]: path_prefix must not be empty", i)
				}
			}
		}
	}
	if c.Server.ReadTimeout < 0 || c.Server.IdleTimeout < 0 {
		return fmt.Errorf("server.read_timeout and server.idle_timeout must not be negative (0 disables)")
	}
	if _, err := ipfilter.ParseCIDRs(c.TrustedProxies); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("tls.cert_file must not be empty when tls is enabled")
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.key_file must not be empty when tls is enabled")
		}
	}
	return nil
}
