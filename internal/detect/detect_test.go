package detect

import "testing"

func categories(ms []Match) map[string]int {
	out := map[string]int{}
	for _, m := range ms {
		out[m.Category]++
	}
	return out
}

func TestScanFindsExpectedCategories(t *testing.T) {
	text := `Employee record
Name: Jane Example
SSN: 219-09-9999
DOB: 03/14/1985
Card on file: 4111 1111 1111 1111
Email: jane.example@example.com
Phone: (555) 867-5309
Driver's License No: D12345678
Passport number 483959274
Routing: 021000021 account number 000123456789
Medicare MBI 1EG4-TE5-MK73
MRN: 8675309 Diagnosis: E11.9
`
	cats := categories(Scan(text))
	want := []string{
		"SSN", "Date of Birth", "Credit Card", "Email Address", "Phone Number",
		"Driver's License", "Passport Number", "Bank Routing Number",
		"Bank Account Number", "Medicare ID (HIPAA)",
		"Medical Record Number (HIPAA)", "Diagnosis Code (HIPAA)",
	}
	for _, w := range want {
		if cats[w] == 0 {
			t.Errorf("expected a %s finding, got none (found: %v)", w, cats)
		}
	}
}

func TestScanRejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name, text, category string
	}{
		{"ssn area 000", "SSN: 000-12-3456", "SSN"},
		{"ssn area 666", "SSN: 666-12-3456", "SSN"},
		{"ssn group 00", "SSN: 123-00-3456", "SSN"},
		{"luhn failure", "card 4111 1111 1111 1112", "Credit Card"},
		{"unknown card prefix", "card 9111 1111 1111 1111", "Credit Card"},
		{"bad routing checksum", "routing 123456789", "Bank Routing Number"},
		{"bare 9 digits without keyword", "order id 219099999", "SSN"},
		{"date without dob keyword", "invoice date 03/14/1985", "Date of Birth"},
	}
	for _, c := range cases {
		if got := categories(Scan(c.text))[c.category]; got != 0 {
			t.Errorf("%s: expected no %s finding in %q, got %d", c.name, c.category, c.text, got)
		}
	}
}

func TestKeywordGatedDetections(t *testing.T) {
	// With the keyword present the same value should be found.
	cases := []struct {
		text, category string
	}{
		{"employee ssn 219099999", "SSN"},
		{"date of birth: 03/14/1985", "Date of Birth"},
		{"routing number 021000021", "Bank Routing Number"},
		{"patient mrn 8675309", "Medical Record Number (HIPAA)"},
	}
	for _, c := range cases {
		if got := categories(Scan(c.text))[c.category]; got == 0 {
			t.Errorf("expected %s finding in %q", c.category, c.text)
		}
	}
}

func TestITINDetected(t *testing.T) {
	cats := categories(Scan("taxpayer ITIN 912-83-4567"))
	if cats["ITIN"] == 0 {
		t.Errorf("expected ITIN finding, got %v", cats)
	}
	if cats["SSN"] != 0 {
		t.Errorf("9xx number must not also be reported as SSN, got %v", cats)
	}
}

func TestLuhn(t *testing.T) {
	if !luhn("4111111111111111") {
		t.Error("4111111111111111 should pass Luhn")
	}
	if luhn("4111111111111112") {
		t.Error("4111111111111112 should fail Luhn")
	}
}

func TestABARouting(t *testing.T) {
	if !validABARouting("021000021") {
		t.Error("021000021 should pass the ABA checksum")
	}
	if validABARouting("123456789") {
		t.Error("123456789 should fail the ABA checksum")
	}
}

func TestConfidenceLevels(t *testing.T) {
	for _, m := range Scan("SSN: 219-09-9999") {
		if m.Category == "SSN" && m.Confidence != High {
			t.Errorf("dashed SSN should be high confidence, got %s", m.Confidence)
		}
	}
	for _, m := range Scan("customer email jane@example.com") {
		if m.Category == "Email Address" && m.Confidence != Medium {
			t.Errorf("email should be medium confidence, got %s", m.Confidence)
		}
	}
}

func TestCategoriesDistinctAndStable(t *testing.T) {
	cats := Categories()
	if len(cats) == 0 {
		t.Fatal("no categories")
	}
	seen := map[string]bool{}
	for _, c := range cats {
		if seen[c] {
			t.Errorf("duplicate category %q", c)
		}
		seen[c] = true
	}
	for _, want := range []string{"SSN", "Email Address", "Phone Number"} {
		if !seen[want] {
			t.Errorf("missing category %q", want)
		}
	}
}

func TestScanOnlyFiltersCategories(t *testing.T) {
	text := "ssn 123-45-6789 email a@b.com phone 412-823-0629"
	all := ScanOnly(text, nil)
	if len(all) == 0 {
		t.Fatal("expected matches with nil filter")
	}
	only := ScanOnly(text, map[string]bool{"Email Address": true})
	if len(only) == 0 {
		t.Fatal("expected email match")
	}
	for _, m := range only {
		if m.Category != "Email Address" {
			t.Errorf("unselected category %q leaked through", m.Category)
		}
	}
	if len(ScanOnly(text, map[string]bool{"Passport Number": true})) != 0 {
		t.Error("expected no matches for a category absent from the text")
	}
}

func TestNormalizeCategories(t *testing.T) {
	got, err := NormalizeCategories([]string{"ssn", "email-address", "Medicare ID (HIPAA)", "SSN"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SSN", "Email Address", "Medicare ID (HIPAA)"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := NormalizeCategories([]string{"Social Security"}); err == nil {
		t.Error("unknown name must error, not silently drop")
	}
}

func TestCMMCMarkings(t *testing.T) {
	find := func(text string) []Match {
		var out []Match
		for _, m := range Scan(text) {
			if m.Category == CategoryCMMC {
				out = append(out, m)
			}
		}
		return out
	}

	// TLP markings: high confidence in every common spelling.
	for _, text := range []string{"TLP:RED", "TLP: Amber", "tlp red", "TLP-GREEN", "TLP:AMBER+STRICT"} {
		ms := find(text)
		if len(ms) != 1 || ms[0].Confidence != High {
			t.Errorf("%q: got %+v, want one high-confidence match", text, ms)
		}
	}
	// TLP:CLEAR marks shareable material — not flagged.
	if ms := find("TLP:CLEAR"); len(ms) != 0 {
		t.Errorf("TLP:CLEAR should not match, got %+v", ms)
	}

	// Spelled-out phrases: high.
	for _, text := range []string{
		"This document contains Controlled Unclassified Information.",
		"handling of federal contract information (FCI)",
	} {
		ms := find(text)
		if len(ms) == 0 || ms[0].Confidence != High {
			t.Errorf("%q: got %+v, want high-confidence match", text, ms)
		}
	}

	// Banner form self-boosts to high; bare acronym alone is medium.
	if ms := find("CUI//SP-PRIV"); len(ms) != 1 || ms[0].Confidence != High || ms[0].Value != "CUI//SP-PRIV" {
		t.Errorf("banner: got %+v", ms)
	}
	if ms := find("Header: CUI\nBody text."); len(ms) != 1 || ms[0].Confidence != Medium {
		t.Errorf("bare CUI: got %+v", ms)
	}
	if ms := find("FCI"); len(ms) != 1 || ms[0].Confidence != Medium {
		t.Errorf("bare FCI: got %+v", ms)
	}
	// Acronym near corroborating language boosts to high.
	if ms := find("marked CUI per DFARS 252.204-7012"); len(ms) == 0 || ms[0].Confidence != High {
		t.Errorf("boosted CUI: got %+v", ms)
	}

	// Lowercase and embedded forms are not markings.
	for _, text := range []string{"la persona a cui ho parlato", "fci", "CUIDADO", "SFCI9"} {
		if ms := find(text); len(ms) != 0 {
			t.Errorf("%q should not match, got %+v", text, ms)
		}
	}
}

func TestCMMCScopeIndicators(t *testing.T) {
	find := func(text string) []Match {
		var out []Match
		for _, m := range Scan(text) {
			if m.Category == CategoryCMMCScope {
				out = append(out, m)
			}
		}
		return out
	}

	// Distinctive references: high on their own.
	for _, text := range []string{
		"subject to the International Traffic in Arms Regulations",
		"this material is export-controlled",
		"Distribution Statement D applies",
		"per DFARS 252.204-7012 flowdown",
	} {
		ms := find(text)
		if len(ms) == 0 || ms[0].Confidence != High {
			t.Errorf("%q: got %+v, want high-confidence match", text, ms)
		}
	}

	// Bare acronyms: medium alone, high with export language nearby.
	if ms := find("ITAR restrictions apply"); len(ms) != 1 || ms[0].Confidence != Medium {
		t.Errorf("bare ITAR: got %+v", ms)
	}
	if ms := find("ITAR: defense articles and technical data"); len(ms) == 0 || ms[0].Confidence != High {
		t.Errorf("boosted ITAR: got %+v", ms)
	}
	if ms := find("classified EAR99 under the export regulations"); len(ms) == 0 || ms[0].Confidence != High {
		t.Errorf("EAR99: got %+v", ms)
	}

	// 800-171: medium alone, high with NIST context.
	if ms := find("see 800-171 controls"); len(ms) != 1 || ms[0].Confidence != Medium {
		t.Errorf("bare 800-171: got %+v", ms)
	}
	if ms := find("NIST SP 800-171 Rev 2 assessment"); len(ms) == 0 || ms[0].Confidence != High {
		t.Errorf("NIST 800-171: got %+v", ms)
	}

	// DoD contract number needs a contract-style label; medium when kept.
	if ms := find("Contract No. W91QUZ-18-C-0022"); len(ms) != 1 || ms[0].Confidence != Medium || ms[0].Value != "W91QUZ-18-C-0022" {
		t.Errorf("PIID with label: got %+v", ms)
	}
	if ms := find("part W91QUZ-18-C-0022 in inventory"); len(ms) != 0 {
		t.Errorf("PIID without label should not match, got %+v", ms)
	}

	// Non-indicators: lowercase itar, embedded uppercase, public statement A.
	for _, text := range []string{"itar", "GUITAR CENTER", "MILITARY", "Distribution Statement A"} {
		if ms := find(text); len(ms) != 0 {
			t.Errorf("%q should not match, got %+v", text, ms)
		}
	}
}

// A card followed by more digits (CVV, expiry, the next column) used to be
// swallowed into one over-long run that failed Luhn, hiding the card.
func TestCreditCardFollowedByDigits(t *testing.T) {
	cases := []struct{ text, want string }{
		{"card 4111111111111111 123", "4111111111111111"},
		{"card: 4111 1111 1111 1111 12/26", "4111 1111 1111 1111"},
		{"4111-1111-1111-1111 2026", "4111-1111-1111-1111"},
		{"ref 123 4111 1111 1111 1111", "4111 1111 1111 1111"},
		{"amex 3782 822463 10005 1234", "3782 822463 10005"},
		{"plain 4111 1111 1111 1111 end", "4111 1111 1111 1111"},
	}
	for _, c := range cases {
		var got []string
		for _, m := range Scan(c.text) {
			if m.Category == "Credit Card" {
				got = append(got, m.Value)
			}
		}
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("Scan(%q) cards = %q, want [%q]", c.text, got, c.want)
		}
	}
}

func TestCreditCardsAdjacent(t *testing.T) {
	text := "4111 1111 1111 1111 5555 5555 5555 4444"
	n := 0
	for _, m := range Scan(text) {
		if m.Category == "Credit Card" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("Scan(%q) found %d cards, want 2", text, n)
	}
}
