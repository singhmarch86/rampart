package eventlog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempLog(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadParsesValidLines(t *testing.T) {
	path := writeTempLog(t, []string{
		`{"time":"2026-01-01T00:00:00Z","action":"block","layer":"waf","reason":"x","client_ip":"1.2.3.4","method":"GET","path":"/a"}`,
		`{"time":"2026-01-01T00:01:00Z","action":"block","layer":"apiabuse","reason":"y","client_ip":"5.6.7.8","method":"POST","path":"/b"}`,
	})
	evts, errs, err := Read(path, time.Time{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(errs) != 0 {
		t.Fatalf("expected no parse errors, got %v", errs)
	}
	if len(evts) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evts))
	}
	if evts[0].Layer != "waf" || evts[1].Layer != "apiabuse" {
		t.Errorf("unexpected layers: %v", evts)
	}
}

func TestReadSkipsUnparseableLinesWithoutAborting(t *testing.T) {
	path := writeTempLog(t, []string{
		`{"time":"2026-01-01T00:00:00Z","action":"block","layer":"waf","reason":"x","client_ip":"1.2.3.4"}`,
		`not json at all, e.g. a truncated line from a crash mid-write`,
		`{"time":"2026-01-01T00:02:00Z","action":"block","layer":"schema","reason":"z","client_ip":"9.9.9.9"}`,
	})
	evts, errs, err := Read(path, time.Time{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(evts) != 2 {
		t.Fatalf("expected 2 valid events despite one bad line, got %d", len(evts))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 parse error reported, got %d", len(errs))
	}
}

func TestReadFiltersBySince(t *testing.T) {
	path := writeTempLog(t, []string{
		`{"time":"2026-01-01T00:00:00Z","action":"block","layer":"waf","reason":"old","client_ip":"1.1.1.1"}`,
		`{"time":"2026-01-02T00:00:00Z","action":"block","layer":"waf","reason":"new","client_ip":"2.2.2.2"}`,
	})
	cutoff, _ := time.Parse(time.RFC3339, "2026-01-01T12:00:00Z")
	evts, _, err := Read(path, cutoff)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(evts) != 1 || evts[0].Reason != "new" {
		t.Fatalf("expected only the event after cutoff, got %v", evts)
	}
}

func TestReadMissingFile(t *testing.T) {
	_, _, err := Read(filepath.Join(t.TempDir(), "does-not-exist.jsonl"), time.Time{})
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
