package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/singhmarch86/rampart/internal/events"
)

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func TestAggregateEmpty(t *testing.T) {
	s := Aggregate(nil)
	if s.TotalEvents != 0 {
		t.Errorf("expected 0 events, got %d", s.TotalEvents)
	}
	if len(s.TopAttackers) != 0 || len(s.MultiVector) != 0 || len(s.Bursts) != 0 {
		t.Errorf("expected all-empty summary for no events, got %+v", s)
	}
}

func TestAggregateTopAttackersAndReasons(t *testing.T) {
	evts := []events.Event{
		{Time: mustParse(t, "2026-01-01T00:00:00Z"), Layer: "waf", Reason: "sqli", ClientIP: "1.1.1.1", Path: "/search"},
		{Time: mustParse(t, "2026-01-01T00:00:01Z"), Layer: "waf", Reason: "sqli", ClientIP: "1.1.1.1", Path: "/search"},
		{Time: mustParse(t, "2026-01-01T00:00:02Z"), Layer: "waf", Reason: "xss", ClientIP: "2.2.2.2", Path: "/comment"},
	}
	s := Aggregate(evts)

	if s.TotalEvents != 3 {
		t.Errorf("expected 3 total events, got %d", s.TotalEvents)
	}
	if len(s.TopAttackers) == 0 || s.TopAttackers[0].IP != "1.1.1.1" || s.TopAttackers[0].Count != 2 {
		t.Errorf("expected 1.1.1.1 as top attacker with count 2, got %+v", s.TopAttackers)
	}
	if len(s.TopReasons) == 0 || s.TopReasons[0].Reason != "sqli" || s.TopReasons[0].Count != 2 {
		t.Errorf("expected sqli as top reason with count 2, got %+v", s.TopReasons)
	}
	if len(s.TopPaths) == 0 || s.TopPaths[0].Path != "/search" || s.TopPaths[0].Count != 2 {
		t.Errorf("expected /search as top path with count 2, got %+v", s.TopPaths)
	}
	if !s.WindowStart.Equal(mustParse(t, "2026-01-01T00:00:00Z")) {
		t.Errorf("unexpected window start: %v", s.WindowStart)
	}
	if !s.WindowEnd.Equal(mustParse(t, "2026-01-01T00:00:02Z")) {
		t.Errorf("unexpected window end: %v", s.WindowEnd)
	}
}

func TestAggregateMultiVectorRequiresMultipleDistinctLayers(t *testing.T) {
	evts := []events.Event{
		{Time: mustParse(t, "2026-01-01T00:00:00Z"), Layer: "waf", Reason: "sqli", ClientIP: "1.1.1.1"},
		{Time: mustParse(t, "2026-01-01T00:00:01Z"), Layer: "apiabuse", Reason: "brute-force", ClientIP: "1.1.1.1"},
		// Single-layer IP: should NOT show up as multi-vector even with repeat hits.
		{Time: mustParse(t, "2026-01-01T00:00:02Z"), Layer: "waf", Reason: "xss", ClientIP: "2.2.2.2"},
		{Time: mustParse(t, "2026-01-01T00:00:03Z"), Layer: "waf", Reason: "xss", ClientIP: "2.2.2.2"},
	}
	s := Aggregate(evts)

	if len(s.MultiVector) != 1 {
		t.Fatalf("expected exactly 1 multi-vector IP, got %+v", s.MultiVector)
	}
	mv := s.MultiVector[0]
	if mv.IP != "1.1.1.1" || mv.Count != 2 {
		t.Errorf("unexpected multi-vector entry: %+v", mv)
	}
	if len(mv.Layers) != 2 || mv.Layers[0] != "apiabuse" || mv.Layers[1] != "waf" {
		t.Errorf("expected sorted [apiabuse waf], got %v", mv.Layers)
	}
}

func TestAggregateDetectsBurst(t *testing.T) {
	base := mustParse(t, "2026-01-01T00:00:00Z")
	var evts []events.Event
	// 12 events from the same IP within one minute -> well within the
	// 5-minute burst window and above burstMinCount (10).
	for i := 0; i < 12; i++ {
		evts = append(evts, events.Event{
			Time: base.Add(time.Duration(i) * time.Second), Layer: "ratelimit", Reason: "rps exceeded", ClientIP: "3.3.3.3",
		})
	}
	s := Aggregate(evts)

	if len(s.Bursts) != 1 {
		t.Fatalf("expected exactly 1 burst, got %+v", s.Bursts)
	}
	if s.Bursts[0].IP != "3.3.3.3" || s.Bursts[0].Count != 12 {
		t.Errorf("unexpected burst: %+v", s.Bursts[0])
	}
}

func TestAggregateNoBurstBelowThreshold(t *testing.T) {
	base := mustParse(t, "2026-01-01T00:00:00Z")
	var evts []events.Event
	for i := 0; i < 5; i++ {
		evts = append(evts, events.Event{
			Time: base.Add(time.Duration(i) * time.Second), Layer: "waf", Reason: "sqli", ClientIP: "4.4.4.4",
		})
	}
	s := Aggregate(evts)
	if len(s.Bursts) != 0 {
		t.Errorf("expected no burst below burstMinCount, got %+v", s.Bursts)
	}
}

func TestAggregateKeepsDetectEventsOutOfBlockStatistics(t *testing.T) {
	at := mustParse(t, "2026-01-01T00:00:00Z")
	evts := []events.Event{
		{Time: at, Action: events.ActionBlock, Layer: "waf", Reason: "sqli", ClientIP: "203.0.113.1", Path: "/a"},
		{Time: at.Add(time.Hour), Action: events.ActionDetect, Layer: "waf", Reason: "sqli", ClientIP: "203.0.113.9", Path: "/b"},
	}
	s := Aggregate(evts)
	if s.TotalEvents != 1 || s.WouldBlock != 1 {
		t.Fatalf("expected 1 block and 1 would-block, got %+v", s)
	}
	if len(s.TopAttackers) != 1 || s.TopAttackers[0].IP != "203.0.113.1" {
		t.Fatalf("detect-only IP should not be a top attacker: %+v", s.TopAttackers)
	}
	if !s.WindowEnd.Equal(at) {
		t.Fatalf("detect event should not stretch the window: %v", s.WindowEnd)
	}

	onlyDetect := Aggregate(evts[1:])
	if onlyDetect.TotalEvents != 0 || onlyDetect.WouldBlock != 1 {
		t.Fatalf("detect-only log: %+v", onlyDetect)
	}
	if !strings.Contains(Report(onlyDetect, ""), "1 further request(s) were logged in detect mode") {
		t.Fatalf("report should mention the detect-mode events")
	}
}
