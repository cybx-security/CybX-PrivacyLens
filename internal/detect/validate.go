package detect

import (
	"strconv"
	"strings"
)

// validSSN applies SSA issuance rules: area cannot be 000, 666, or 900-999;
// group cannot be 00; serial cannot be 0000.
func validSSN(area, group, serial string) bool {
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// validITINGroup checks the middle two digits of an ITIN, which must fall in
// the IRS-assigned ranges 70-88, 90-92, or 94-99.
func validITINGroup(group string) bool {
	n, err := strconv.Atoi(group)
	if err != nil {
		return false
	}
	return (n >= 70 && n <= 88) || (n >= 90 && n <= 92) || (n >= 94 && n <= 99)
}

// validCreditCard strips separators then requires a plausible length, a known
// issuer prefix, and a passing Luhn checksum.
func validCreditCard(raw string) bool {
	d := digitsOnly(raw)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	if allSameDigit(d) {
		return false
	}
	return knownIssuerPrefix(d) && luhn(d)
}

// cardWithin locates a valid card number inside text[start:end], a run of
// digit groups joined by single spaces or hyphens. The whole run is tried
// first; failing that, every contiguous sequence of whole groups is, leftmost
// then longest — so "4111 1111 1111 1111 123" (card, then CVV) and
// "4111111111111111 12/26" (card, then expiry) still report the card. Only
// whole groups are considered: a card never starts or stops mid-group.
func cardWithin(text string, start, end int) (from, to int, ok bool) {
	type group struct{ s, e int }
	var groups []group
	for i := start; i < end; {
		if text[i] == ' ' || text[i] == '-' {
			i++
			continue
		}
		j := i
		for j < end && text[j] >= '0' && text[j] <= '9' {
			j++
		}
		groups = append(groups, group{i, j})
		i = j
	}
	for i := range groups {
		for j := len(groups) - 1; j >= i; j-- {
			if validCreditCard(text[groups[i].s:groups[j].e]) {
				return groups[i].s, groups[j].e, true
			}
		}
	}
	return 0, 0, false
}

func knownIssuerPrefix(d string) bool {
	first2 := d[:2]
	first4, _ := strconv.Atoi(d[:4])
	switch {
	case d[0] == '4': // Visa
		return true
	case first2 >= "51" && first2 <= "55": // Mastercard
		return true
	case first4 >= 2221 && first4 <= 2720: // Mastercard (new range)
		return true
	case first2 == "34" || first2 == "37": // American Express
		return true
	case strings.HasPrefix(d, "6011") || first2 == "65": // Discover
		return true
	case first2 == "35": // JCB
		return true
	case first2 == "30" || first2 == "36" || first2 == "38": // Diners Club
		return true
	}
	return false
}

func luhn(digits string) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// validABARouting applies the ABA checksum used by US bank routing numbers.
func validABARouting(d string) bool {
	if len(d) != 9 {
		return false
	}
	weights := [9]int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += weights[i] * int(d[i]-'0')
	}
	return sum > 0 && sum%10 == 0
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func allSameDigit(d string) bool {
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}
