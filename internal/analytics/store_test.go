package analytics

import (
	"testing"
	"time"

	"github.com/singhmarch86/rampart/internal/events"
)

func newTestStore(t *testing.T) (*events.Logger, *Store) {
	t.Helper()
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	store := New(logger)
	t.Cleanup(store.Close)
	return logger, store
}

func TestSnapshotReflectsLoggedEvents(t *testing.T) {
	logger, store := newTestStore(t)

	logger.Log(events.Event{Action: events.ActionBlock, Layer: "waf", Reason: "xss", ClientIP: "203.0.113.1"})
	logger.Log(events.Event{Action: events.ActionBlock, Layer: "waf", Reason: "sqli", ClientIP: "203.0.113.1"})
	logger.Log(events.Event{Action: events.ActionBlock, Layer: "ratelimit", Reason: "too fast", ClientIP: "203.0.113.2"})

	stats := store.Snapshot()

	if stats.TotalEvents != 3 {
		t.Fatalf("expected 3 total events, got %d", stats.TotalEvents)
	}
	if stats.ByLayer["waf"] != 2 {
		t.Fatalf("expected 2 waf events, got %d", stats.ByLayer["waf"])
	}
	if stats.ByLayer["ratelimit"] != 1 {
		t.Fatalf("expected 1 ratelimit event, got %d", stats.ByLayer["ratelimit"])
	}
}

func TestTopAttackersSortedByCount(t *testing.T) {
	logger, store := newTestStore(t)

	for i := 0; i < 3; i++ {
		logger.Log(events.Event{Layer: "waf", Reason: "x", ClientIP: "203.0.113.9"})
	}
	logger.Log(events.Event{Layer: "waf", Reason: "x", ClientIP: "203.0.113.10"})

	stats := store.Snapshot()
	if len(stats.TopAttackers) < 2 {
		t.Fatalf("expected at least 2 attackers, got %d", len(stats.TopAttackers))
	}
	if stats.TopAttackers[0].IP != "203.0.113.9" || stats.TopAttackers[0].Count != 3 {
		t.Fatalf("expected top attacker to be .9 with count 3, got %+v", stats.TopAttackers[0])
	}
}

func TestTopReasonsGroupedByLayerAndReason(t *testing.T) {
	logger, store := newTestStore(t)

	logger.Log(events.Event{Layer: "waf", Reason: "SQL injection detected", ClientIP: "203.0.113.1"})
	logger.Log(events.Event{Layer: "waf", Reason: "SQL injection detected", ClientIP: "203.0.113.2"})
	logger.Log(events.Event{Layer: "apiabuse", Reason: "SQL injection detected", ClientIP: "203.0.113.3"})

	stats := store.Snapshot()

	var wafCount, apiabuseCount int
	for _, rc := range stats.TopReasons {
		if rc.Layer == "waf" && rc.Reason == "SQL injection detected" {
			wafCount = rc.Count
		}
		if rc.Layer == "apiabuse" && rc.Reason == "SQL injection detected" {
			apiabuseCount = rc.Count
		}
	}
	if wafCount != 2 {
		t.Fatalf("expected waf/SQL injection detected count 2, got %d", wafCount)
	}
	if apiabuseCount != 1 {
		t.Fatalf("expected same reason text under a different layer to be tracked separately, got %d", apiabuseCount)
	}
}

func TestRecentEventsNewestFirstAndBounded(t *testing.T) {
	logger, store := newTestStore(t)

	for i := 0; i < maxRecentEvents+10; i++ {
		logger.Log(events.Event{Layer: "waf", Reason: "x", ClientIP: "203.0.113.1", Path: "/n"})
	}
	logger.Log(events.Event{Layer: "waf", Reason: "last", ClientIP: "203.0.113.1"})

	stats := store.Snapshot()
	if len(stats.RecentEvents) != maxRecentEvents {
		t.Fatalf("expected recent events bounded to %d, got %d", maxRecentEvents, len(stats.RecentEvents))
	}
	if stats.RecentEvents[0].Reason != "last" {
		t.Fatalf("expected newest event first, got reason %q", stats.RecentEvents[0].Reason)
	}
}

func TestTimelineBucketsByMinute(t *testing.T) {
	logger, store := newTestStore(t)

	// Anchored 5s into a minute (not time.Now() directly) so the +30s/+90s
	// offsets below deterministically land in the intended minute buckets
	// regardless of what second the test happens to run on.
	now := time.Now().UTC().Truncate(time.Minute).Add(5 * time.Second)
	logger.Log(events.Event{Time: now, Layer: "waf", Reason: "x", ClientIP: "1.2.3.4"})
	logger.Log(events.Event{Time: now.Add(30 * time.Second), Layer: "waf", Reason: "x", ClientIP: "1.2.3.4"})
	logger.Log(events.Event{Time: now.Add(90 * time.Second), Layer: "waf", Reason: "x", ClientIP: "1.2.3.4"})

	stats := store.Snapshot()
	total := 0
	for _, b := range stats.Timeline {
		total += b.Count
	}
	if total != 3 {
		t.Fatalf("expected 3 events across timeline buckets, got %d", total)
	}
	// The first two events share a minute, the third is in the next one, so
	// there should be exactly 2 distinct buckets.
	if len(stats.Timeline) != 2 {
		t.Fatalf("expected 2 distinct minute buckets, got %d: %+v", len(stats.Timeline), stats.Timeline)
	}
}

func TestSnapshotAfterCloseDoesNotHang(t *testing.T) {
	logger, err := events.NewLogger("")
	if err != nil {
		t.Fatal(err)
	}
	store := New(logger)
	store.Close()

	done := make(chan struct{})
	go func() {
		store.Snapshot()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Snapshot() hung after Close()")
	}
}
