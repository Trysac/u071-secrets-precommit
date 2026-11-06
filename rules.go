package secretsprecommit

import (
	"regexp"
	"slices"
)

// Rule is one detection rule.
type Rule struct {
	// ID is the stable identifier reported in findings.
	ID string

	// Description is a short human-readable name.
	Description string

	// Pattern is an RE2 expression matched against each line.
	Pattern *regexp.Regexp

	// SecretGroup is the capture group holding the secret; 0 means the whole match.
	SecretGroup int

	// MinEntropy is the minimum Shannon entropy, in bits per byte, of the
	// captured secret. Zero disables the check.
	MinEntropy float64
}

// wrapPrefix opens the word-boundary wrapper of every token rule.
const wrapPrefix = `(?:^|[^A-Za-z0-9_])(`

// wrapSuffix closes the word-boundary wrapper of every token rule.
const wrapSuffix = `)(?:[^A-Za-z0-9_]|$)`

// tokenRule builds a rule whose secret is the whole token, wrapped so that a
// token touching another word character is not reported.
func tokenRule(id, description, pattern string) Rule {
	re := regexp.MustCompile(wrapPrefix + pattern + wrapSuffix)
	return Rule{ID: id, Description: description, Pattern: re, SecretGroup: 1}
}

var defaultRules = []Rule{
	tokenRule("aws-access-key-id", "AWS access key ID", `(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`),
	tokenRule("github-token", "GitHub personal, OAuth, user, server or refresh token", `gh[pousr]_[A-Za-z0-9]{36}`),
	tokenRule("github-fine-grained-pat", "GitHub fine-grained personal access token", `github_pat_[A-Za-z0-9_]{82}`),
	tokenRule("slack-token", "Slack token", `xox[baprs]-[A-Za-z0-9-]{10,200}`),
	tokenRule("stripe-live-key", "Stripe live secret or restricted key", `(?:sk|rk)_live_[A-Za-z0-9]{24,99}`),
	tokenRule("google-api-key", "Google API key", `AIza[A-Za-z0-9_-]{35}`),
	tokenRule("anthropic-api-key", "Anthropic API key", `sk-ant-api03-[A-Za-z0-9_-]{93}AA`),
	tokenRule("openai-api-key", "OpenAI API key", `sk-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}`),
	tokenRule("private-key-block", "Private key block header", `-----BEGIN[ A-Z]*PRIVATE KEY-----`),
	{
		ID:          "generic-assignment",
		Description: "High-entropy value assigned to a key, secret, token or password",
		Pattern:     regexp.MustCompile(`(?i)(?:key|secret|token|password|passwd|api_key)\s*[:=]\s*["']([^"'\s]{12,})["']`),
		SecretGroup: 1,
		MinEntropy:  3.5,
	},
}

// DefaultRules returns the ten built-in rules in a stable order. The returned
// slice is a copy; modifying it does not affect later calls.
func DefaultRules() []Rule {
	return slices.Clone(defaultRules)
}
