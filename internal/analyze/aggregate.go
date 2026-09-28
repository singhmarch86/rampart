// Package analyze turns a window of Rampart's block-event log into an
// operational triage report: a deterministic aggregation (this package),
// optionally narrated by an LLM (see llm.go).
//
// Scope, stated plainly because it's easy to overclaim: every event
// Rampart logs is a Block decision (see internal/events) recording only
// time/layer/reason/IP/method/path — no request payload, and no record of
// allowed traffic. That means this package can summarize and triage
// attacks Rampart already caught; it cannot discover attacks that slipped
// through (those never appear in this log by definition), and it has no
// payload content to draft a new detection rule from. Don't ask it for
// either — it isn't built to answer them.
package analyze

import (
	"sort"
	"time"

	"github.com/gauravdeepsingh/rampart/internal/events"
)

const (
	topN            = 10
	multiLayerMinIP = 2               // an IP must hit at least this many distinct layers to be "multi-vector"
	burstWindow     = 5 * time.Minute // events from one IP within this window count toward a burst
	burstMinCount   = 10              // events within burstWindow needed to flag a burst
)

type IPCount struct {
	IP    string
	Count int
}

type ReasonCount struct {
	Layer  string
	Reason string
	Count  int
}

type PathCount struct {
	Path  string
	Count int
}

// MultiVectorIP is a client IP whose blocked requests spanned more than
// one detection layer — a stronger signal of a deliberate, scripted
// attacker than a single-layer count alone, since it means the same
// source tried more than one technique.
type MultiVectorIP struct {
	IP     string
	Layers []string
	Count  int
}

// Burst is a run of at least burstMinCount blocked requests from one IP
// within a single burstWindow-wide window — a signal of automated,
// scripted traffic rather than a human clicking around.
type Burst struct {
	IP     string
	Start  time.Time
	End    time.Time
	Count  int
	Layers []string
}

type Summary struct {
	WindowStart  time.Time
	WindowEnd    time.Time
	TotalEvents  int
	ByLayer      map[string]int
	TopAttackers []IPCount
	TopReasons   []ReasonCount
	TopPaths     []PathCount
	MultiVector  []MultiVectorIP
	Bursts       []Burst
}

// Aggregate computes a Summary from a batch of events. It's pure and
// deterministic — no LLM involved — so it's fully unit-testable and safe
// to trust on its own even without the narrative step in llm.go.
func Aggregate(evts []events.Event) Summary {
	s := Summary{ByLayer: make(map[string]int)}
	if len(evts) == 0 {
		return s
	}

	byIP := make(map[string]int)
	byReasonKey := make(map[string]*ReasonCount)
	byPath := make(map[string]int)
	layersByIP := make(map[string]map[string]bool)

	for _, e := range evts {
		if s.WindowStart.IsZero() || e.Time.Before(s.WindowStart) {
			s.WindowStart = e.Time
		}
		if e.Time.After(s.WindowEnd) {
			s.WindowEnd = e.Time
		}
		s.TotalEvents++
		s.ByLayer[e.Layer]++
		if e.ClientIP != "" {
			byIP[e.ClientIP]++
			if layersByIP[e.ClientIP] == nil {
				layersByIP[e.ClientIP] = make(map[string]bool)
			}
			layersByIP[e.ClientIP][e.Layer] = true
		}
		if e.Path != "" {
			byPath[e.Path]++
		}
		key := e.Layer + "\x00" + e.Reason
		if rc, ok := byReasonKey[key]; ok {
			rc.Count++
		} else {
			byReasonKey[key] = &ReasonCount{Layer: e.Layer, Reason: e.Reason, Count: 1}
		}
	}

	s.TopAttackers = topIPCounts(byIP, topN)
	s.TopPaths = topPathCounts(byPath, topN)

	reasons := make([]ReasonCount, 0, len(byReasonKey))
	for _, rc := range byReasonKey {
		reasons = append(reasons, *rc)
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i].Count > reasons[j].Count })
	if len(reasons) > topN {
		reasons = reasons[:topN]
	}
	s.TopReasons = reasons

	for ip, layers := range layersByIP {
		if len(layers) >= multiLayerMinIP {
			names := make([]string, 0, len(layers))
			for l := range layers {
				names = append(names, l)
			}
			sort.Strings(names)
			s.MultiVector = append(s.MultiVector, MultiVectorIP{IP: ip, Layers: names, Count: byIP[ip]})
		}
	}
	sort.Slice(s.MultiVector, func(i, j int) bool { return s.MultiVector[i].Count > s.MultiVector[j].Count })

	s.Bursts = detectBursts(evts)

	return s
}

func topIPCounts(m map[string]int, n int) []IPCount {
	out := make([]IPCount, 0, len(m))
	for ip, c := range m {
		out = append(out, IPCount{IP: ip, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topPathCounts(m map[string]int, n int) []PathCount {
	out := make([]PathCount, 0, len(m))
	for p, c := range m {
		out = append(out, PathCount{Path: p, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// detectBursts groups each IP's events into fixed, non-overlapping
// burstWindow-wide buckets (bucketed by floor(time/window), not a sliding
// window) and reports every bucket with at least burstMinCount events.
// A fixed-bucket approach is a deliberate simplification over a true
// sliding window: it can under-count a burst that straddles a bucket
// boundary, but it's O(n) and trivially deterministic to test, which
// matters more for a triage signal than catching every boundary case.
func detectBursts(evts []events.Event) []Burst {
	type bucketKey struct {
		ip     string
		bucket int64
	}
	buckets := make(map[bucketKey][]events.Event)
	for _, e := range evts {
		if e.ClientIP == "" {
			continue
		}
		b := e.Time.Unix() / int64(burstWindow.Seconds())
		k := bucketKey{ip: e.ClientIP, bucket: b}
		buckets[k] = append(buckets[k], e)
	}

	var bursts []Burst
	for k, es := range buckets {
		if len(es) < burstMinCount {
			continue
		}
		start, end := es[0].Time, es[0].Time
		layerSet := make(map[string]bool)
		for _, e := range es {
			if e.Time.Before(start) {
				start = e.Time
			}
			if e.Time.After(end) {
				end = e.Time
			}
			layerSet[e.Layer] = true
		}
		layers := make([]string, 0, len(layerSet))
		for l := range layerSet {
			layers = append(layers, l)
		}
		sort.Strings(layers)
		bursts = append(bursts, Burst{IP: k.ip, Start: start, End: end, Count: len(es), Layers: layers})
	}
	sort.Slice(bursts, func(i, j int) bool { return bursts[i].Count > bursts[j].Count })
	return bursts
}
