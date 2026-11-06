package secretsprecommit

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// redactedSuffix is appended to the visible prefix of every secret.
const redactedSuffix = "****"

// maxVisibleRunes is the largest number of leading runes Redacted may show.
const maxVisibleRunes = 4

// Finding is one potential secret. It never contains the full secret.
type Finding struct {
	// RuleID is the identifier of the rule that matched.
	RuleID string `json:"ruleId"`

	// Path is the path as given to the scanner.
	Path string `json:"path"`

	// Line is the 1-based line number.
	Line int `json:"line"`

	// Column is the 1-based column of the secret, counted in runes.
	Column int `json:"column"`

	// Redacted is the first runes of the secret followed by four asterisks.
	// It does not reveal the length of the secret. Secrets shorter than eight
	// runes show fewer than four runes so they are never printed in full.
	Redacted string `json:"redacted"`
}

// String formats the finding as path:line:column: ruleId: redacted.
// A path containing control characters is quoted.
func (f Finding) String() string {
	return fmt.Sprintf("%s:%d:%d: %s: %s", displayPath(f.Path), f.Line, f.Column, f.RuleID, f.Redacted)
}

// displayPath quotes paths that could manipulate a terminal.
func displayPath(p string) string {
	if strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return strconv.Quote(p)
	}
	return p
}

// redact returns the visible prefix of secret followed by four asterisks.
func redact(secret string) string {
	n := utf8.RuneCountInString(secret) / 2
	n = min(n, maxVisibleRunes)
	var b strings.Builder
	shown := 0
	for _, r := range secret {
		if shown >= n {
			break
		}
		if unicode.IsControl(r) {
			r = '?'
		}
		b.WriteRune(r)
		shown++
	}
	b.WriteString(redactedSuffix)
	return b.String()
}

// shannon returns the Shannon entropy of s in bits per byte.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	bits := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		bits -= p * math.Log2(p)
	}
	return bits
}
