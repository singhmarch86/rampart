package analyze

import (
	"fmt"
	"strings"
	"time"
)

// Report renders a Summary (and an optional LLM narrative, empty string
// if none was requested or configured) as Markdown. The deterministic
// tables come first and stand on their own — the narrative, when present,
// is clearly labeled as generated commentary on top of them, not a
// separate source of truth.
func Report(s Summary, narrative string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Rampart attack triage report\n\n")
	fmt.Fprintf(&b, "Generated %s. Window: %s to %s. %d blocked requests.\n\n",
		time.Now().UTC().Format(time.RFC3339), s.WindowStart.Format(time.RFC3339), s.WindowEnd.Format(time.RFC3339), s.TotalEvents)
	fmt.Fprintf(&b, "> Scope: this covers requests Rampart already blocked. It cannot show attacks that were missed (those aren't logged) and has no request payloads to draft new rules from — see [docs/ANALYZE.md](../docs/ANALYZE.md).\n\n")

	if s.WouldBlock > 0 {
		fmt.Fprintf(&b, "> %d further request(s) were logged in detect mode (the WAF would have blocked them but let them through). They are not counted in any figure below.\n\n", s.WouldBlock)
	}

	if s.TotalEvents == 0 {
		b.WriteString("No blocked requests in this window.\n")
		writeRules(&b, s)
		return b.String()
	}

	if narrative != "" {
		b.WriteString("## Summary\n\n")
		b.WriteString(narrative)
		b.WriteString("\n\n")
	}

	b.WriteString("## By layer\n\n")
	b.WriteString("| Layer | Count |\n|---|---|\n")
	for layer, count := range s.ByLayer {
		fmt.Fprintf(&b, "| %s | %d |\n", layer, count)
	}
	b.WriteString("\n")

	b.WriteString("## Top attacker IPs\n\n")
	b.WriteString("| IP | Blocked requests |\n|---|---|\n")
	for _, ip := range s.TopAttackers {
		fmt.Fprintf(&b, "| %s | %d |\n", ip.IP, ip.Count)
	}
	b.WriteString("\n")

	b.WriteString("## Top block reasons\n\n")
	b.WriteString("| Layer | Reason | Count |\n|---|---|---|\n")
	for _, r := range s.TopReasons {
		fmt.Fprintf(&b, "| %s | %s | %d |\n", r.Layer, r.Reason, r.Count)
	}
	b.WriteString("\n")

	writeRules(&b, s)

	b.WriteString("## Most-targeted paths\n\n")
	b.WriteString("| Path | Count |\n|---|---|\n")
	for _, p := range s.TopPaths {
		fmt.Fprintf(&b, "| %s | %d |\n", p.Path, p.Count)
	}
	b.WriteString("\n")

	if len(s.MultiVector) > 0 {
		b.WriteString("## IPs that triggered more than one detection layer\n\n")
		b.WriteString("| IP | Layers | Total blocked requests |\n|---|---|---|\n")
		for _, m := range s.MultiVector {
			fmt.Fprintf(&b, "| %s | %s | %d |\n", m.IP, strings.Join(m.Layers, ", "), m.Count)
		}
		b.WriteString("\n")
	}

	if len(s.Bursts) > 0 {
		b.WriteString("## Traffic bursts\n\n")
		b.WriteString("_At least 10 blocked requests from one IP within a 5-minute window — a signal of automated/scripted traffic._\n\n")
		b.WriteString("| IP | Count | Start | End | Layers |\n|---|---|---|---|---|\n")
		for _, burst := range s.Bursts {
			fmt.Fprintf(&b, "| %s | %d | %s | %s | %s |\n",
				burst.IP, burst.Count, burst.Start.Format(time.RFC3339), burst.End.Format(time.RFC3339), strings.Join(burst.Layers, ", "))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// writeRules renders which WAF rules fired. It counts blocked and would-block
// (detect mode) events alike, since the question it answers is "which rules".
func writeRules(b *strings.Builder, s Summary) {
	if len(s.TopRules) == 0 {
		return
	}
	b.WriteString("\n## Top WAF rules (blocked and would-block)\n\n")
	b.WriteString("| Rule | Class | What it detected | Hits |\n|---|---|---|---|\n")
	for _, r := range s.TopRules {
		fmt.Fprintf(b, "| %d | %s | %s | %d |\n", r.ID, r.Class, r.Msg, r.Count)
	}
	b.WriteString("\n")
}
