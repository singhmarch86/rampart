// Command rampart-analyze reads a window of Rampart's JSONL event log and
// produces a Markdown triage report: top attackers, top block reasons,
// multi-layer attackers, and traffic bursts. It's a separate binary from
// rampart itself deliberately — the core proxy has no dependency on this
// package or on any external API, so running the firewall never requires
// network access beyond your own upstream. See docs/ANALYZE.md for the
// tool's scope and — just as important — what it can't do.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gauravdeepsingh/rampart/internal/analyze"
	"github.com/gauravdeepsingh/rampart/internal/eventlog"
)

func main() {
	os.Exit(run())
}

func run() int {
	eventsPath := flag.String("events", "rampart-events.jsonl", "path to Rampart's JSONL event log")
	since := flag.Duration("since", 7*24*time.Hour, "only include events from this far back (e.g. 24h, 168h)")
	out := flag.String("out", "rampart-report.md", "path to write the Markdown report to")
	narrate := flag.Bool("narrate", true, "add an LLM-written plain-English summary on top of the tables (requires ANTHROPIC_API_KEY; skipped automatically if unset)")
	flag.Parse()

	cutoff := time.Time{}
	if *since > 0 {
		cutoff = time.Now().Add(-*since)
	}

	evts, parseErrs, err := eventlog.Read(*eventsPath, cutoff)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rampart-analyze:", err)
		return 2
	}
	for _, e := range parseErrs {
		fmt.Fprintln(os.Stderr, "rampart-analyze: skipping unparseable line:", e)
	}

	summary := analyze.Aggregate(evts)

	var narrative string
	if *narrate {
		if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
			n := analyze.NewNarrator(apiKey)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			text, narrateErr := n.Narrate(ctx, summary)
			if narrateErr != nil {
				fmt.Fprintln(os.Stderr, "rampart-analyze: narration failed, continuing with tables only:", narrateErr)
			} else {
				narrative = text
			}
		} else {
			fmt.Fprintln(os.Stderr, "rampart-analyze: ANTHROPIC_API_KEY not set, skipping narration (tables-only report)")
		}
	}

	report := analyze.Report(summary, narrative)

	// #nosec G304 G703 -- path is the -out CLI flag the operator passes at
	// invocation, not from a request.
	if err := os.WriteFile(*out, []byte(report), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "rampart-analyze:", err)
		return 2
	}

	fmt.Printf("rampart-analyze: %d events in window, report written to %s\n", summary.TotalEvents, *out)
	return 0
}
