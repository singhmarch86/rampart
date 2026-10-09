package waf

import (
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"

	"github.com/singhmarch86/rampart/internal/events"
)

const (
	maxEventRules = 10
	// First rule ID of the range Rampart treats as operator-defined.
	customRuleIDMin = 1000000
	// CRS's anomaly-score evaluation rules (inbound, outbound). They only
	// summarize the others, and the event already carries their score.
	inboundEvalRuleID  = 949110
	outboundEvalRuleID = 959100
)

// matchedDetail extracts what an event should say about why the WAF acted:
// the anomaly score and the rules that contributed.
//
// tx.MatchedRules() holds about 60 entries even for a clean request, almost
// all CRS bookkeeping (initialization and paranoia-level gate rules). Those
// have no severity and no message. A real detection has a message and a
// severity; so does every custom rule that sets one. A rule counts when it
// has a message and either a severity or a custom-range ID, and is not an
// evaluation rule. Capped at maxEventRules; the rest are counted.
func matchedDetail(rules []types.MatchedRule) (score int, out []events.Rule, omitted int) {
	for _, mr := range rules {
		meta := mr.Rule()
		id := meta.ID()
		if id == inboundEvalRuleID || id == outboundEvalRuleID {
			score = evalScore(mr)
			continue
		}
		msg := mr.Message()
		sev := int(meta.Severity())
		if msg == "" || (sev < 0 && id < customRuleIDMin) {
			continue
		}
		if len(out) >= maxEventRules {
			omitted++
			continue
		}
		out = append(out, events.Rule{
			ID: id, Msg: msg, Severity: sev,
			PL: paranoiaLevel(meta.Tags()), Tags: attackTags(meta.Tags()),
			Var: matchedVariable(mr),
		})
	}
	return score, out, omitted
}

// evalScore reads the score from the evaluation rule's matched data (the
// value of TX:blocking_*_anomaly_score) rather than parsing the message.
func evalScore(mr types.MatchedRule) int {
	for _, md := range mr.MatchedDatas() {
		if n, err := strconv.Atoi(strings.TrimSpace(md.Value())); err == nil {
			return n
		}
	}
	return 0
}

func paranoiaLevel(tags []string) int {
	for _, t := range tags {
		if rest, ok := strings.CutPrefix(t, "paranoia-level/"); ok {
			if n, err := strconv.Atoi(rest); err == nil {
				return n
			}
		}
	}
	return 0
}

func attackTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if strings.HasPrefix(t, "attack-") {
			out = append(out, t)
		}
	}
	return out
}

// matchedVariable is the first matched variable's name and key ("ARGS:q"),
// never its value.
func matchedVariable(mr types.MatchedRule) string {
	for _, md := range mr.MatchedDatas() {
		name := md.Variable().Name()
		if k := md.Key(); k != "" {
			return name + ":" + k
		}
		return name
	}
	return ""
}
