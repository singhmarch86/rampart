package analytics

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"time"
)

//go:embed dashboard.html
var dashboardHTML []byte

// Server exposes the Store over HTTP: the dashboard page itself, a JSON
// snapshot endpoint for it to poll, and a Server-Sent Events stream for a
// live-updating view. This is meant to run on its own listener, separate
// from the public-facing proxy port — the analytics dashboard has no
// authentication of its own yet (see docs/ROADMAP.md), so exposing it on
// the same port as the protected application would leak attack data to
// whoever can reach the app.
type Server struct {
	store *Store
}

func NewServer(store *Store) *Server {
	return &Server{store: store}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(dashboardHTML)
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.store.Snapshot())
	})

	mux.HandleFunc("/api/stream", s.streamHandler)

	return mux
}

// streamHandler pushes a fresh Stats snapshot over Server-Sent Events every
// time a new event lands, so the dashboard updates live without polling.
// It subscribes its own channel on the underlying Logger (via a second
// Store-less path isn't needed: we just re-snapshot on a short tick, which
// is simpler and cheap at this scale than plumbing a second subscriber
// through the Store).
func (s *Server) streamHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	writeSnapshot := func() bool {
		b, err := json.Marshal(s.store.Snapshot())
		if err != nil {
			return false
		}
		if _, err := w.Write([]byte("data: ")); err != nil {
			return false
		}
		if _, err := w.Write(b); err != nil {
			return false
		}
		if _, err := w.Write([]byte("\n\n")); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !writeSnapshot() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !writeSnapshot() {
				return
			}
		}
	}
}
