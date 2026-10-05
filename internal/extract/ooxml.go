package extract

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

// maxOOXMLText caps the text extracted from one Office document. Zip
// compression means a few-megabyte file can expand to gigabytes (by accident
// or by design); without a cap, one such document exhausts memory and takes
// the whole scan down with it. Far above any real document — the default
// 50 MB size limit keeps genuine files well under it. A variable so tests
// can lower it.
var maxOOXMLText = 512 << 20

// checkOOXMLSize fails extraction once a document's text passes the cap, so
// the file is reported as unreadable (a visible gap) instead of crashing
// the scan.
func checkOOXMLSize(sb *strings.Builder) error {
	if sb.Len() > maxOOXMLText {
		return fmt.Errorf("document expands to more than %d MB of text; not scanned (possible decompression bomb)", maxOOXMLText>>20)
	}
	return nil
}

// docxText extracts text from a Word document: the main body plus headers
// and footers. Runs within a paragraph are concatenated without separators
// (Word splits sentences into runs at formatting boundaries), and paragraphs
// become lines.
func docxText(path string) (string, error) {
	return ooxmlText(path, func(name string) bool {
		return name == "word/document.xml" ||
			strings.HasPrefix(name, "word/header") ||
			strings.HasPrefix(name, "word/footer")
	}, "")
}

// pptxText extracts text from slide bodies and speaker notes.
func pptxText(path string) (string, error) {
	return ooxmlText(path, func(name string) bool {
		return strings.HasPrefix(name, "ppt/slides/slide") ||
			strings.HasPrefix(name, "ppt/notesSlides/notesSlide")
	}, "")
}

// ooxmlText walks the zip entries selected by want and collects the character
// data of <t>/<v> elements. runSep is inserted after each text element;
// paragraph and row ends become newlines.
func ooxmlText(path string, want func(string) bool, runSep string) (string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer zr.Close()

	var names []string
	byName := map[string]*zip.File{}
	for _, f := range zr.File {
		if want(f.Name) {
			names = append(names, f.Name)
			byName[f.Name] = f
		}
	}
	sort.Strings(names)

	var sb strings.Builder
	for _, name := range names {
		rc, err := byName[name].Open()
		if err != nil {
			return "", err
		}
		err = collectXMLText(rc, &sb, runSep)
		rc.Close()
		if err != nil {
			return "", err
		}
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// collectXMLText appends the character data of <t> elements (w:t, a:t, and
// shared-string <t>) to sb. Paragraph (<p>) and table-row (<tr>/<row>) ends
// become newlines so findings get sensible line numbers.
func collectXMLText(r io.Reader, sb *strings.Builder, runSep string) error {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	depth := 0 // nesting depth inside a <t> element
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "t" || depth > 0 {
				depth++
			}
		case xml.EndElement:
			if depth > 0 {
				depth--
				if depth == 0 {
					sb.WriteString(runSep)
				}
			}
			if t.Name.Local == "p" || t.Name.Local == "tr" || t.Name.Local == "row" {
				sb.WriteByte('\n')
			}
		case xml.CharData:
			if depth > 0 {
				sb.Write(t)
				if err := checkOOXMLSize(sb); err != nil {
					return err
				}
			}
		}
	}
}

// xlsxText extracts spreadsheet content: all shared strings plus the raw
// values of non-shared-string cells (numbers, inline strings, formula
// results). Shared-string cells hold an index in <v>, not content, so those
// are skipped to avoid flagging meaningless index numbers.
func xlsxText(path string) (string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer zr.Close()

	var sb strings.Builder
	var sheetNames []string
	byName := map[string]*zip.File{}
	for _, f := range zr.File {
		if f.Name == "xl/sharedStrings.xml" {
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			err = collectXMLText(rc, &sb, "\n")
			rc.Close()
			if err != nil {
				return "", err
			}
		}
		if strings.HasPrefix(f.Name, "xl/worksheets/") && strings.HasSuffix(f.Name, ".xml") {
			sheetNames = append(sheetNames, f.Name)
			byName[f.Name] = f
		}
	}
	sort.Strings(sheetNames)
	for _, name := range sheetNames {
		rc, err := byName[name].Open()
		if err != nil {
			return "", err
		}
		err = collectSheetValues(rc, &sb)
		rc.Close()
		if err != nil {
			return "", err
		}
	}
	return sb.String(), nil
}

// collectSheetValues appends cell values from a worksheet XML stream,
// skipping shared-string index cells (t="s"). Rows become lines and cells
// are space-separated so adjacent numeric cells don't merge.
func collectSheetValues(r io.Reader, sb *strings.Builder) error {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	sharedCell := false
	inValue := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "c":
				sharedCell = false
				for _, a := range t.Attr {
					if a.Name.Local == "t" && a.Value == "s" {
						sharedCell = true
					}
				}
			case "v", "is", "t":
				if !sharedCell {
					inValue = true
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "v", "is", "t":
				if inValue {
					sb.WriteByte(' ')
				}
				inValue = false
			case "row":
				sb.WriteByte('\n')
			}
		case xml.CharData:
			if inValue {
				sb.Write(t)
				if err := checkOOXMLSize(sb); err != nil {
					return err
				}
			}
		}
	}
}
