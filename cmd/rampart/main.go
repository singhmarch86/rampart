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
	"github.com/gauravdeepsingh/rampart/internal/proxy"
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
	if cfg.Dashboard.Enabled {
		analyticsStore = analytics.New(logger)
		dashboardServer = &http.Server{
			Addr:              cfg.Dashboard.Listen,
			Handler:           analytics.NewServer(analyticsStore).Handler(),
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
}
