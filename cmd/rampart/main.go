// Command rampart runs the firewall reverse proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gauravdeepsingh/rampart/internal/analytics"
	"github.com/gauravdeepsingh/rampart/internal/config"
	"github.com/gauravdeepsingh/rampart/internal/events"
	"github.com/gauravdeepsingh/rampart/internal/oidcauth"
	"github.com/gauravdeepsingh/rampart/internal/proxy"
	"github.com/gauravdeepsingh/rampart/internal/ratelimit"
)

func main() {
	configPath := flag.String("config", "configs/rampart.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	logger, err := events.NewLogger(cfg.Logging.EventsPath)
	if err != nil {
		log.Fatalf("events logger: %v", err)
	}
	defer logger.Close()

	p, err := proxy.New(cfg, logger)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	defer p.Close()

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("rampart listening on %s, proxying to %s", cfg.Listen, cfg.Upstream)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	var dashboardServer *http.Server
	var analyticsStore *analytics.Store
	var dashboardLimiter *ratelimit.Limiter
	if cfg.Dashboard.Enabled {
		analyticsStore = analytics.New(logger)
		dashboardHandler := analytics.NewServer(analyticsStore).Handler()

		if cfg.OIDC.Enabled && cfg.OIDC.DashboardAuth.Enabled {
			discoverCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			provider, err := oidcauth.NewProvider(discoverCtx, cfg.OIDC.IssuerURL)
			cancel()
			if err != nil {
				log.Fatalf("OIDC discovery for dashboard auth: %v", err)
			}
			dashAuth := oidcauth.NewDashboardAuth(provider, cfg.OIDC.DashboardAuth, cfg.OIDC.RolesClaim, logger)

			mux := http.NewServeMux()
			mux.Handle("/auth/", dashAuth.Handler())
			mux.Handle("/", dashAuth.RequireAuth(dashboardHandler))
			dashboardHandler = mux
			log.Printf("dashboard requires OIDC login (issuer: %s)", cfg.OIDC.IssuerURL)
		}

		// The dashboard server previously had no rate limiting of its own at
		// all - the main proxy chain gets it, but this is a separate
		// http.Server that never passed through that chain. Found during a
		// hardening pass, not live-caught; see finding #7 in docs/FINDINGS.md.
		if cfg.Dashboard.RateLimit.Enabled {
			dashboardLimiter = ratelimit.New(
				cfg.Dashboard.RateLimit.RequestsPerSecond,
				cfg.Dashboard.RateLimit.Burst,
				cfg.Dashboard.RateLimit.MaxConcurrentPerIP,
				cfg.Dashboard.RateLimit.IdleTimeout,
			)
			dashboardHandler = ratelimit.Middleware(dashboardLimiter, "dashboard-ratelimit", logger, dashboardHandler)
		}

		dashboardServer = &http.Server{
			Addr:              cfg.Dashboard.Listen,
			Handler:           dashboardHandler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			log.Printf("rampart dashboard listening on %s", cfg.Dashboard.Listen)
			if err := dashboardServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("dashboard server: %v", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	if dashboardServer != nil {
		if err := dashboardServer.Shutdown(ctx); err != nil {
			log.Printf("dashboard shutdown error: %v", err)
		}
	}
	if analyticsStore != nil {
		analyticsStore.Close()
	}
	if dashboardLimiter != nil {
		dashboardLimiter.Close()
	}
}
