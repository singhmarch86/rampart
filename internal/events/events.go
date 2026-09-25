// Package events defines the structured event log that every enforcement
// decision (allow/block) is written to. This is the seed of the Phase 4
// analytics pipeline: every layer added later (WAF, API abuse detection)
// writes through the same Logger so the dashboard has one event stream.
package events

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

type Event struct {
	Time     time.Time `json:"time"`
	Action   Action    `json:"action"`
	Layer    string    `json:"layer"` // e.g. "ipfilter", "ratelimit", "waf"
	Reason   string    `json:"reason"`
	ClientIP string    `json:"client_ip"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
}

// Logger writes events as JSON Lines. It is safe for concurrent use.
type Logger struct {
	mu  sync.Mutex
	out io.WriteCloser
}

// NewLogger opens path for appending. An empty path yields a no-op logger.
func NewLogger(path string) (*Logger, error) {
	if path == "" {
		return &Logger{out: nopWriteCloser{io.Discard}}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Logger{out: f}, nil
}

func (l *Logger) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("events: marshal error: %v", err)
		return
	}
	b = append(b, '\n')
	if _, err := l.out.Write(b); err != nil {
		log.Printf("events: write error: %v", err)
	}
}

func (l *Logger) Close() error {
	return l.out.Close()
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
