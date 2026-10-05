package extract

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzCollectXMLText(f *testing.F) {
	f.Add([]byte(`<w:p><w:r><w:t>SSN 219-09-9999</w:t></w:r></w:p>`))
	f.Add([]byte("not xml"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var out strings.Builder
		_ = collectXMLText(bytes.NewReader(data), &out, "")
	})
}
