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
	// ActionDetect marks a request the WAF would have blocked but, because
	// waf.mode is "detect", let through. It is NOT a block: consumers that
	// count blocks (the dashboard, rampart-analyze) must keep it out of
	// those counts and report it separately.
	ActionDetect Action = "detect"
)

type Event struct {
	Time     time.Time `json:"time"`
	Action   Action    `json:"action"`
	Layer    string    `json:"layer"` // e.g. "ipfilter", "ratelimit", "waf"
	Reason   string    `json:"reason"`
	ClientIP string    `json:"client_ip"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`

	// WAF events only. Reason for a CRS block is always the generic
	// "Inbound Anomaly Score Exceeded"; these say why. See
	// docs/SPEC-matched-rule-ids.md.
	Score        int    `json:"score,omitempty"`         // the anomaly score that crossed the threshold
	Rules        []Rule `json:"rules,omitempty"`         // contributing rules, in match order
	RulesOmitted int    `json:"rules_omitted,omitempty"` // contributing rules beyond the cap
}

// Rule is one WAF rule that matched a request.
type Rule struct {
	ID       int      `json:"id"`
	Msg      string   `json:"msg"`
	Severity int      `json:"severity"`
	PL       int      `json:"pl,omitempty"`   // paranoia level the rule belongs to, if tagged
	Tags     []string `json:"tags,omitempty"` // attack-* tags only, e.g. "attack-sqli"
	// Var is the variable that matched ("ARGS:q"). Never its value: that is
	// attacker input and may contain secrets.
	Var string `json:"var,omitempty"`
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
