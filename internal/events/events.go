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

// Logger writes events as JSON Lines and, optionally, fans them out live to
// in-process subscribers (see Subscribe) — this is how the Phase 4
// analytics dashboard gets events in real time without tailing the log
// file. The file is the durable record; subscriptions are best-effort.
type Logger struct {
	mu          sync.Mutex
	out         io.WriteCloser
	subscribers map[int]chan Event
	nextSubID   int
}

// NewLogger opens path for appending. An empty path yields a no-op logger.
func NewLogger(path string) (*Logger, error) {
	l := &Logger{subscribers: make(map[int]chan Event)}
	if path == "" {
		l.out = nopWriteCloser{io.Discard}
		return l, nil
	}
	// 0o600: this file records attack traffic detail (source IPs, request
	// paths), so it shouldn't be group/world-readable by default.
	// #nosec G304 -- path is Logging.EventsPath from the operator's own
	// config file, set at process start, not from a request.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.out = f
	return l, nil
}

func (l *Logger) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.mu.Lock()
	b, err := json.Marshal(e)
	if err != nil {
		l.mu.Unlock()
		log.Printf("events: marshal error: %v", err)
		return
	}
	b = append(b, '\n')
	if _, err := l.out.Write(b); err != nil {
		log.Printf("events: write error: %v", err)
	}
	for _, ch := range l.subscribers {
		select {
		case ch <- e:
		default:
			// Subscriber isn't keeping up; drop the event for it rather than
			// block the request path. The JSONL file remains the durable record.
		}
	}
	l.mu.Unlock()
}

// Subscribe registers a live listener for every future Log call. Call the
// returned cancel func when done to release the channel.
func (l *Logger) Subscribe() (<-chan Event, func()) {
	l.mu.Lock()
	id := l.nextSubID
	l.nextSubID++
	ch := make(chan Event, 256)
	l.subscribers[id] = ch
	l.mu.Unlock()

	cancel := func() {
		l.mu.Lock()
		if _, ok := l.subscribers[id]; ok {
			delete(l.subscribers, id)
			close(ch)
		}
		l.mu.Unlock()
	}
	return ch, cancel
}

func (l *Logger) Close() error {
	return l.out.Close()
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
