package detect

import "regexp"

// Context keyword sets. A keyword hit near a match either boosts its
// confidence or, for loose patterns, is required for the match to count.
var (
	kwSSN      = regexp.MustCompile(`(?i)\b(ssn|soc(ial)?[\s.-]*sec|tax\s*id|tin)\b`)
	kwDOB      = regexp.MustCompile(`(?i)\b(dob|date\s*of\s*birth|birth\s*date|born)\b`)
	kwDL       = regexp.MustCompile(`(?i)(driver'?s?\s*(license|licence|lic)\b|\bdl\s*(#|no\.?|num)|\blicense\s*(#|no\.?|number))`)
	kwPassport = regexp.MustCompile(`(?i)\bpassport\b`)
	kwRouting  = regexp.MustCompile(`(?i)\b(routing|aba|rtn)\b`)
	kwAccount  = regexp.MustCompile(`(?i)((bank|checking|savings)\s+account|\b(account|acct)\.?\s*(number|no\.?|num|#))`)
	kwPhone    = regexp.MustCompile(`(?i)\b(phone|tel(ephone)?|mobile|cell|fax|call)\b`)
	kwMedicare = regexp.MustCompile(`(?i)\b(medicare|mbi|beneficiary)\b`)
	kwMRN      = regexp.MustCompile(`(?i)\b(mrn|medical\s*record|patient\s*(id|no\.?|number))\b`)
	kwDiag     = regexp.MustCompile(`(?i)(diagnos|icd[- ]?10|icd[- ]?9|\bdx\b)`)
	// kwCMMC boosts bare CUI/FCI acronym hits. cui\s*// is deliberate: the
	// keyword window includes the match itself, so a CUI//… banner marking
	// self-boosts to high while a bare "CUI" needs corroboration nearby.
	kwCMMC = regexp.MustCompile(`(?i)(controlled\s+unclassified|federal\s+contract|cui\s*//|\bcontrolled\b|dissemination|distribution\s+statement|\bdfars\b|800[-\s]?171|\bcmmc\b|\bnoforn\b|\bfouo\b|export[-\s]controlled|\bitar\b)`)
	// kwExport corroborates bare ITAR/EAR99 acronyms (the acronyms
	// themselves are deliberately absent so a match can't self-boost).
	kwExport = regexp.MustCompile(`(?i)(export|munitions|defense\s+article|\busml\b|arms\s+regulations|commerce\s+control|technical\s+data)`)
	// kwNIST corroborates bare 800-171 references.
	kwNIST = regexp.MustCompile(`(?i)(\bnist\b|\bsp\b|\brev(ision)?\b|assessment|compliance|\bdfars\b|\bcmmc\b)`)
	// kwContract gates DoD contract-number (PIID) shaped strings, which are
	// otherwise indistinguishable from part numbers.
	kwContract = regexp.MustCompile(`(?i)\b(contract|award|task\s+order|delivery\s+order|solicitation|procurement|\bdfars\b|\bcage\b)`)
)

// CategoryCMMC is the display name for CMMC document-marking findings —
// referenced from the report layer, which leaves these matches unmasked
// (the marking itself is the finding, not a secret value).
const CategoryCMMC = "Document Marking (CMMC)"

// CategoryCMMCScope flags content that suggests a document falls under CMMC
// even when no CUI/FCI/TLP marking is present — export-control regimes,
// DFARS safeguarding clauses, NIST 800-171 references, DoD distribution
// statements, DoD contract numbers. Scope-creep detection: a hit on an
// unmarked document on an unmanaged share is worth a look. Matches are
// indicators, not secrets, so reports leave them unmasked too.
const CategoryCMMCScope = "Scope Indicator (CMMC)"

// reDate matches common written date formats (used for date-of-birth
// detection, which additionally requires a DOB keyword nearby).
var reDate = regexp.MustCompile(`(?i)\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b|\b(jan(uary)?|feb(ruary)?|mar(ch)?|apr(il)?|may|jun(e)?|jul(y)?|aug(ust)?|sep(t(ember)?)?|oct(ober)?|nov(ember)?|dec(ember)?)\.?\s+\d{1,2}(st|nd|rd|th)?,?\s+\d{4}\b`)

// mbiChar classes: Medicare Beneficiary Identifiers exclude the letters
// B, I, L, O, S, Z. Format is C A AN N - A AN N - A A N N (11 chars).
const (
	mbiAlpha = `[AC-HJ-KM-NP-RT-Y]`
	mbiAlnum = `[AC-HJ-KM-NP-RT-Y0-9]`
)

var detectors = []detector{
	{
		category: "SSN",
		re:       regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`),
		validate: func(g []string) bool { return validSSN(g[1], g[2], g[3]) },
		keywords: kwSSN,
		base:     High, boosted: High,
	},
	{
		// SSN written without separators or with spaces is indistinguishable
		// from an arbitrary 9-digit number, so a keyword is required.
		category: "SSN",
		re:       regexp.MustCompile(`\b(\d{3})(\d{2})(\d{4})\b`),
		validate: func(g []string) bool { return validSSN(g[1], g[2], g[3]) },
		keywords: kwSSN, needKeyword: true,
		base: Medium, boosted: High,
	},
	{
		category: "SSN",
		re:       regexp.MustCompile(`\b(\d{3}) (\d{2}) (\d{4})\b`),
		validate: func(g []string) bool { return validSSN(g[1], g[2], g[3]) },
		keywords: kwSSN, needKeyword: true,
		base: Medium, boosted: High,
	},
	{
		category: "ITIN",
		re:       regexp.MustCompile(`\b(9\d{2})-(\d{2})-(\d{4})\b`),
		validate: func(g []string) bool { return validITINGroup(g[2]) },
		keywords: kwSSN,
		base:     High, boosted: High,
	},
	{
		// The pattern grabs any run of 13-19 digits with single separators,
		// which overruns a real card that is followed by more digits (a CVV,
		// an expiry, the next CSV column); cardWithin picks the card back
		// out of the run.
		category: "Credit Card",
		re:       regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
		narrow:   cardWithin,
		base:     High, boosted: High,
	},
	{
		category: "Email Address",
		re:       regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		base:     Medium, boosted: Medium,
	},
	{
		category: "Phone Number",
		re:       regexp.MustCompile(`(?:\+?1[-. ]?)?\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b`),
		keywords: kwPhone,
		base:     Medium, boosted: High,
	},
	{
		category: "Date of Birth",
		re:       reDate,
		keywords: kwDOB, needKeyword: true,
		base: Medium, boosted: High,
	},
	{
		category: "Driver's License",
		re:       regexp.MustCompile(`\b(?:[A-Za-z]{1,2}[- ]?\d{4,12}|\d{5,12})\b`),
		keywords: kwDL, needKeyword: true,
		base: Medium, boosted: Medium,
	},
	{
		category: "Passport Number",
		re:       regexp.MustCompile(`\b[A-Za-z]?\d{8,9}\b`),
		keywords: kwPassport, needKeyword: true,
		base: Medium, boosted: Medium,
	},
	{
		category: "Bank Routing Number",
		re:       regexp.MustCompile(`\b(\d{9})\b`),
		validate: func(g []string) bool { return validABARouting(g[1]) },
		keywords: kwRouting, needKeyword: true,
		base: High, boosted: High,
	},
	{
		category: "Bank Account Number",
		re:       regexp.MustCompile(`\b\d{6,17}\b`),
		keywords: kwAccount, needKeyword: true,
		base: Medium, boosted: Medium,
	},
	{
		category: "Medicare ID (HIPAA)",
		re: regexp.MustCompile(
			`\b[1-9]` + mbiAlpha + mbiAlnum + `\d-?` + mbiAlpha + mbiAlnum + `\d-?` + mbiAlpha + mbiAlpha + `\d{2}\b`),
		keywords: kwMedicare,
		base:     Medium, boosted: High,
	},
	{
		category: "Medical Record Number (HIPAA)",
		re:       regexp.MustCompile(`\b\d{5,10}\b`),
		keywords: kwMRN, needKeyword: true,
		base: Medium, boosted: Medium,
	},
	{
		category: "Diagnosis Code (HIPAA)",
		re:       regexp.MustCompile(`\b[A-TV-Z]\d{2}\.\d{1,4}\b`),
		keywords: kwDiag, needKeyword: true,
		base: Medium, boosted: Medium,
	},
	{
		// Spelled-out CMMC-regulated data descriptions.
		category: CategoryCMMC,
		re:       regexp.MustCompile(`(?i)\b(controlled\s+unclassified\s+information|federal\s+contract\s+information)\b`),
		base:     High, boosted: High,
	},
	{
		// CUI banner (CUI//SP-PRIV) or bare acronym. Uppercase only: "cui"
		// is an everyday Italian word, and mixed case is never a marking.
		category: CategoryCMMC,
		re:       regexp.MustCompile(`\bCUI(?://[A-Z0-9/+=\-]+)?\b`),
		keywords: kwCMMC,
		base:     Medium, boosted: High,
	},
	{
		// Federal Contract Information acronym, uppercase only.
		category: CategoryCMMC,
		re:       regexp.MustCompile(`\bFCI\b`),
		keywords: kwCMMC,
		base:     Medium, boosted: High,
	},
	{
		// Traffic Light Protocol markings (FIRST TLP 2.0). TLP:CLEAR/WHITE
		// mark shareable material and are deliberately not flagged.
		category: CategoryCMMC,
		re:       regexp.MustCompile(`(?i)\bTLP\s*[:\s-]\s*(RED|AMBER(?:\+\s*STRICT)?|GREEN)\b`),
		base:     High, boosted: High,
	},
	{
		// Spelled-out export-control regimes and DoD distribution
		// statements B-F (statement A is approved for public release).
		category: CategoryCMMCScope,
		re:       regexp.MustCompile(`(?i)\b(international\s+traffic\s+in\s+arms\s+regulations|export\s+administration\s+regulations|export[-\s]controlled|distribution\s+statement\s+[B-F])\b`),
		base:     High, boosted: High,
	},
	{
		// ITAR / EAR99 acronyms, uppercase only ("guitar" and "military"
		// never produce a word-bounded uppercase ITAR).
		category: CategoryCMMCScope,
		re:       regexp.MustCompile(`\b(ITAR|EAR99)\b`),
		keywords: kwExport,
		base:     Medium, boosted: High,
	},
	{
		// DFARS 252.204-70xx: the safeguarding/CUI clause family
		// (252.204-7008 through -7021).
		category: CategoryCMMCScope,
		re:       regexp.MustCompile(`\b252\.204-70\d{2}\b`),
		base:     High, boosted: High,
	},
	{
		// NIST SP 800-171 references.
		category: CategoryCMMCScope,
		re:       regexp.MustCompile(`\b800-171[Aa]?\b`),
		keywords: kwNIST,
		base:     Medium, boosted: High,
	},
	{
		// DoD contract number (PIID): DODAAC, fiscal year, instrument type
		// letter, serial (e.g. W91QUZ-18-C-0022). The shape alone is any
		// part number, so a contract-style label is required nearby.
		category: CategoryCMMCScope,
		re:       regexp.MustCompile(`\b[A-Z0-9]{6}-\d{2}-[A-Z]-\d{4}\b`),
		keywords: kwContract, needKeyword: true,
		base: Medium, boosted: Medium,
	},
}
