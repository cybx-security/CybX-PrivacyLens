package detect

import (
	"math/rand"
	"strings"
	"testing"
)

// windowReference is the pre-optimization window implementation, with
// unbounded newline scans. The bounded version must match it byte-for-byte;
// only the search cost may differ.
func windowReference(text string, start, end int) string {
	lo := start - keywordWindow
	if lo < 0 {
		lo = 0
	}
	hi := end + keywordWindow
	if hi > len(text) {
		hi = len(text)
	}
	if nl := strings.LastIndexByte(text[:start], '\n'); nl >= 0 {
		if prev := strings.LastIndexByte(text[:nl], '\n') + 1; prev > lo {
			lo = prev
		}
	}
	if nl := strings.IndexByte(text[end:], '\n'); nl >= 0 && end+nl < hi {
		hi = end + nl
	}
	return text[lo:hi]
}

func TestWindowMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabets := []string{"ab \ncd\n", "abcdef ", "\n\nab\n", "x"}
	for _, alpha := range alphabets {
		for trial := 0; trial < 500; trial++ {
			n := 1 + rng.Intn(600)
			var sb strings.Builder
			for i := 0; i < n; i++ {
				sb.WriteByte(alpha[rng.Intn(len(alpha))])
			}
			text := sb.String()
			start := rng.Intn(len(text) + 1)
			end := start + rng.Intn(len(text)-start+1)
			got, want := window(text, start, end), windowReference(text, start, end)
			if got != want {
				t.Fatalf("window mismatch (alpha %q, len %d, start %d, end %d):\n got %q\nwant %q",
					alpha, len(text), start, end, got, want)
			}
		}
	}
}

// BenchmarkScanSingleLineDense is the pathological shape that made real
// scans crawl: one huge line, dense with matches. Before the window search
// was bounded, this cost O(matches × size) — minutes per file.
func BenchmarkScanSingleLineDense(b *testing.B) {
	text := strings.Repeat("SSN 219-09-9999 pad pad pad ", 20000) // ~560KB, one line
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Scan(text)
	}
}
