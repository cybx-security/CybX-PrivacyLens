// Package detect implements the PII detection engine. Each detector pairs a
// regular expression with optional validation (checksums, issuance rules) and
// context-keyword requirements to keep false positives down.
package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Confidence indicates how likely a match is to be real PII.
type Confidence int

const (
	Low Confidence = iota
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case High:
		return "high"
	case Medium:
		return "medium"
	default:
		return "low"
	}
}

// ParseConfidence converts a user-supplied string to a Confidence level.
func ParseConfidence(s string) (Confidence, bool) {
	switch strings.ToLower(s) {
	case "low":
		return Low, true
	case "medium":
		return Medium, true
	case "high":
		return High, true
	}
	return Low, false
}

// Match is a single PII hit within a text buffer.
type Match struct {
	Category   string
	Value      string
	Start, End int // byte offsets into the scanned text
	Confidence Confidence
}

// keywordWindow is how many bytes of surrounding context are searched for a
// detector's keywords (on each side of the match).
const keywordWindow = 100

type detector struct {
	category string
	re       *regexp.Regexp
	validate func(groups []string) bool // capture-group validation; nil = always valid
	// narrow, if set, replaces validate for patterns whose greedy match can
	// overrun the real value: given a regex match it returns the validated
	// sub-span to report, or ok=false to drop the match entirely.
	narrow      func(text string, start, end int) (from, to int, ok bool)
	keywords    *regexp.Regexp // searched in the window around the match
	needKeyword bool           // drop the match if keywords are absent (vs. just boosting)
	base        Confidence     // confidence without a keyword hit
	boosted     Confidence     // confidence with a keyword hit
}

// NormalizeCategories maps user-supplied category names to the canonical
// display names in Categories(), erroring on any unknown name so a manifest
// typo fails loudly instead of silently scanning for nothing. Matching is
// forgiving: case-insensitive, with punctuation treated as spaces, so
// "ssn", "email-address", and "Medicare ID (HIPAA)" all resolve. Duplicates
// collapse; order follows the input.
func NormalizeCategories(names []string) ([]string, error) {
	canon := map[string]string{}
	for _, c := range Categories() {
		canon[foldCategory(c)] = c
	}
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		c, ok := canon[foldCategory(n)]
		if !ok {
			return nil, fmt.Errorf("unknown PII category %q (valid: %s)", n, strings.Join(Categories(), ", "))
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// foldCategory lowercases and collapses every run of non-alphanumerics to a
// single space, so display names, slugs, and hand-typed variants compare
// equal.
func foldCategory(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		} else {
			space = true
		}
	}
	return b.String()
}

// Categories returns the distinct detector categories in detector order —
// the canonical list for UIs offering per-category scan selection.
func Categories() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range detectors {
		if !seen[d.category] {
			seen[d.category] = true
			out = append(out, d.category)
		}
	}
	return out
}

// Scan runs every detector over text and returns validated matches sorted by
// position. Exact-duplicate spans within the same category are deduplicated,
// and when two categories claim the identical span only the higher-confidence
// one is kept.
func Scan(text string) []Match {
	return ScanOnly(text, nil)
}

// ScanOnly is Scan restricted to the categories named in include (keys as in
// Categories()); nil or empty runs every detector. Unselected detectors are
// skipped entirely, not filtered afterwards, so their regexes never run.
func ScanOnly(text string, include map[string]bool) []Match {
	var out []Match
	for _, d := range detectors {
		if len(include) > 0 && !include[d.category] {
			continue
		}
		for _, idx := range d.spans(text) {
			start, end := idx[0], idx[1]
			if d.validate != nil && !d.validate(groupsFrom(text, idx)) {
				continue
			}
			conf := d.base
			if d.keywords != nil {
				if d.keywords.MatchString(window(text, start, end)) {
					conf = d.boosted
				} else if d.needKeyword {
					continue
				}
			}
			out = append(out, Match{
				Category:   d.category,
				Value:      text[start:end],
				Start:      start,
				End:        end,
				Confidence: conf,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End > out[j].End
		}
		return out[i].Confidence > out[j].Confidence
	})
	return dedupe(out)
}

// spans returns the detector's candidate matches as submatch index slices.
// Detectors with a narrow hook are searched one match at a time so the
// search resumes right after the narrowed span, not after the over-long
// regex match — digits trimmed off the end get their own chance to match.
func (d *detector) spans(text string) [][]int {
	if d.narrow == nil {
		return d.re.FindAllStringSubmatchIndex(text, -1)
	}
	var out [][]int
	for pos := 0; pos < len(text); {
		loc := d.re.FindStringIndex(text[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		if from, to, ok := d.narrow(text, start, end); ok {
			out = append(out, []int{from, to})
			pos = to
		} else {
			pos = end
		}
	}
	return out
}

// dedupe removes repeated hits on the identical span: same-category
// duplicates always collapse, and cross-category duplicates collapse only
// when one match is strictly more confident. Two categories claiming the
// same value at equal confidence are both reported — the ambiguity is real
// and worth showing.
func dedupe(ms []Match) []Match {
	var out []Match
	for _, m := range ms {
		if n := len(out); n > 0 {
			prev := &out[n-1]
			if prev.Start == m.Start && prev.End == m.End {
				if prev.Category == m.Category || prev.Confidence > m.Confidence {
					continue
				}
				if m.Confidence > prev.Confidence {
					*prev = m
					continue
				}
			}
		}
		out = append(out, m)
	}
	return out
}

func groupsFrom(text string, idx []int) []string {
	groups := make([]string, 0, len(idx)/2)
	for i := 0; i < len(idx); i += 2 {
		if idx[i] < 0 {
			groups = append(groups, "")
			continue
		}
		groups = append(groups, text[idx[i]:idx[i+1]])
	}
	return groups
}

// window returns the context searched for keywords: the match's own line
// plus the line above it (labels commonly sit on the preceding line in
// forms), capped at keywordWindow bytes on each side of the match.
//
// The newline searches are bounded to the capped window, never the whole
// text: line boundaries beyond the cap can't change the result, and an
// unbounded search costs O(file size) PER MATCH on huge single-line files
// (minified JS, base64 blobs) — the difference between milliseconds and
// minutes on a match-dense cache file.
func window(text string, start, end int) string {
	lo := start - keywordWindow
	if lo < 0 {
		lo = 0
	}
	hi := end + keywordWindow
	if hi > len(text) {
		hi = len(text)
	}
	if nl := strings.LastIndexByte(text[lo:start], '\n'); nl >= 0 {
		if prev := strings.LastIndexByte(text[lo:lo+nl], '\n'); prev >= 0 {
			lo += prev + 1
		}
	}
	if nl := strings.IndexByte(text[end:hi], '\n'); nl >= 0 {
		hi = end + nl
	}
	return text[lo:hi]
}
