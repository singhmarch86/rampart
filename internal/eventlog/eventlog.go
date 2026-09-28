// Package eventlog reads the JSON Lines event log that events.Logger
// writes (see internal/events). It's a batch reader for offline tools
// (rampart-analyze) — the running proxy never reads its own log back;
// events.Logger.Subscribe is how the live dashboard gets events instead.
package eventlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/singhmarch86/rampart/internal/events"
)

// Read parses every line of path as a JSON-encoded events.Event and
// returns those at or after since (zero time.Time means "all of them").
// A line that fails to parse is skipped with its error appended to the
// returned errs slice rather than aborting the whole read — a log file
// accumulated over time by an always-running process is exactly the kind
// of file that can have a partial trailing line from a crash mid-write.
func Read(path string, since time.Time) (evts []events.Event, errs []error, err error) {
	// #nosec G304 -- path is the -events CLI flag the operator passes at
	// invocation (normally logging.events_path from their own Rampart
	// config), not from a request.
	f, openErr := os.Open(path)
	if openErr != nil {
		return nil, nil, openErr
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Event lines are small JSON objects, but a growing default buffer
	// avoids truncating on an unexpectedly long line rather than silently
	// dropping data.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e events.Event
		if jsonErr := json.Unmarshal(line, &e); jsonErr != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", lineNum, jsonErr))
			continue
		}
		if !since.IsZero() && e.Time.Before(since) {
			continue
		}
		evts = append(evts, e)
	}
	if scanErr := scanner.Err(); scanErr != nil && scanErr != io.EOF {
		return evts, errs, scanErr
	}
	return evts, errs, nil
}
