// Package analytics aggregates Rampart's block/allow event stream into
// something a dashboard can render: totals per layer, top attacker IPs,
// top block reasons, and a per-minute timeline. It consumes events live via
// events.Logger.Subscribe rather than reading the JSONL file, so the
// dashboard reflects traffic in real time without file-tailing.
//
// This is an in-memory, single-process store — it does not persist across
// restarts and does not scale beyond one Rampart instance. That's an
// intentional scope limit for Phase 4: a multi-node, persistent version is
// exactly the kind of thing the planned hosted Console (Phase 6) is for.
package analytics

import (
	"sort"
	"time"

	"github.com/gauravdeepsingh/rampart/internal/events"
)

const (
	maxRecentEvents = 500
	topN            = 10
	timelineWindow  = 60 * time.Minute
)

type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type ReasonCount struct {
	Layer  string `json:"layer"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type TimelineBucket struct {
	Minute time.Time `json:"minute"`
	Count  int       `json:"count"`
}

type Stats struct {
	StartedAt    time.Time        `json:"started_at"`
	TotalEvents  int              `json:"total_events"`
	ByLayer      map[string]int   `json:"by_layer"`
	TopAttackers []IPCount        `json:"top_attackers"`
	TopReasons   []ReasonCount    `json:"top_reasons"`
	Timeline     []TimelineBucket `json:"timeline"`
	RecentEvents []events.Event   `json:"recent_events"`
}

type Store struct {
	startedAt time.Time

	// All fields below are only ever touched by the single ingest
	// goroutine (run), so they need no locking there. Snapshot reads them
	// from that same goroutine via a request/response channel to avoid a
	// separate mutex.
	recent      []events.Event
	byLayer     map[string]int
	byIP        map[string]int
	byReasonKey map[string]*ReasonCount
	byMinute    map[int64]int

	events    <-chan events.Event
	cancel    func()
	snapshots chan chan Stats
	stop      chan struct{}
}

func New(logger *events.Logger) *Store {
	ch, cancel := logger.Subscribe()
	s := &Store{
		startedAt:   time.Now(),
		byLayer:     make(map[string]int),
		byIP:        make(map[string]int),
		byReasonKey: make(map[string]*ReasonCount),
		byMinute:    make(map[int64]int),
		events:      ch,
		cancel:      cancel,
		snapshots:   make(chan chan Stats),
		stop:        make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *Store) Close() {
	close(s.stop)
	s.cancel()
}

func (s *Store) run() {
	for {
		select {
		case e, ok := <-s.events:
			if !ok {
				return
			}
			s.ingest(e)
		case reply := <-s.snapshots:
			// Drain whatever's already buffered before answering, so a
			// snapshot reflects everything logged before the caller's
			// Snapshot() call returned started waiting (Log() places the
			// event in the channel buffer synchronously, so anything
			// logged-before-this-call is already sitting here to drain).
			s.drainPending()
			reply <- s.snapshot()
		case <-s.stop:
			return
		}
	}
}

func (s *Store) drainPending() {
	for {
		select {
		case e, ok := <-s.events:
			if !ok {
				return
			}
			s.ingest(e)
		default:
			return
		}
	}
}

func (s *Store) ingest(e events.Event) {
	s.recent = append(s.recent, e)
	if len(s.recent) > maxRecentEvents {
		s.recent = s.recent[len(s.recent)-maxRecentEvents:]
	}

	s.byLayer[e.Layer]++
	if e.ClientIP != "" {
		s.byIP[e.ClientIP]++
	}

	key := e.Layer + "\x00" + e.Reason
	if rc, ok := s.byReasonKey[key]; ok {
		rc.Count++
	} else {
		s.byReasonKey[key] = &ReasonCount{Layer: e.Layer, Reason: e.Reason, Count: 1}
	}

	minute := e.Time.Truncate(time.Minute).Unix()
	s.byMinute[minute]++
	cutoff := time.Now().Add(-timelineWindow).Truncate(time.Minute).Unix()
	for m := range s.byMinute {
		if m < cutoff {
			delete(s.byMinute, m)
		}
	}
}

// Snapshot returns a point-in-time view of the aggregated stats. Safe to
// call from any goroutine (it round-trips through the ingest goroutine).
func (s *Store) Snapshot() Stats {
	reply := make(chan Stats, 1)
	select {
	case s.snapshots <- reply:
		return <-reply
	case <-s.stop:
		return Stats{StartedAt: s.startedAt}
	}
}

func (s *Store) snapshot() Stats {
	byLayer := make(map[string]int, len(s.byLayer))
	for k, v := range s.byLayer {
		byLayer[k] = v
	}

	attackers := make([]IPCount, 0, len(s.byIP))
	for ip, c := range s.byIP {
		attackers = append(attackers, IPCount{IP: ip, Count: c})
	}
	sort.Slice(attackers, func(i, j int) bool { return attackers[i].Count > attackers[j].Count })
	if len(attackers) > topN {
		attackers = attackers[:topN]
	}

	reasons := make([]ReasonCount, 0, len(s.byReasonKey))
	for _, rc := range s.byReasonKey {
		reasons = append(reasons, *rc)
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i].Count > reasons[j].Count })
	if len(reasons) > topN {
		reasons = reasons[:topN]
	}

	timeline := make([]TimelineBucket, 0, len(s.byMinute))
	for m, c := range s.byMinute {
		timeline = append(timeline, TimelineBucket{Minute: time.Unix(m, 0).UTC(), Count: c})
	}
	sort.Slice(timeline, func(i, j int) bool { return timeline[i].Minute.Before(timeline[j].Minute) })

	recent := make([]events.Event, len(s.recent))
	copy(recent, s.recent)
	// Newest first for display.
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}

	total := 0
	for _, c := range byLayer {
		total += c
	}

	return Stats{
		StartedAt:    s.startedAt,
		TotalEvents:  total,
		ByLayer:      byLayer,
		TopAttackers: attackers,
		TopReasons:   reasons,
		Timeline:     timeline,
		RecentEvents: recent,
	}
}
