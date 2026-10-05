package detect

import "testing"

func FuzzScanOffsets(f *testing.F) {
	f.Add("Employee SSN: 219-09-9999; email jane@example.com")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		for _, m := range Scan(text) {
			if m.Start < 0 || m.End < m.Start || m.End > len(text) {
				t.Fatalf("invalid offsets [%d:%d] for %d bytes", m.Start, m.End, len(text))
			}
			if text[m.Start:m.End] != m.Value {
				t.Fatalf("match value does not match source slice")
			}
		}
	})
}
