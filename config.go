package secretsprecommit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"path"
	"regexp"
	"strings"
)

// MaxConfigSize is the largest configuration, in bytes, that LoadConfig reads.
const MaxConfigSize = 1 << 20

// MaxRules is the largest number of team rules, and of entries in each
// allowlist, accepted in a configuration.
const MaxRules = 100

// MaxPatternBytes is the largest size, in bytes, of a team pattern or
// allowlist entry.
const MaxPatternBytes = 1000

// maxIDBytes is the largest size of a rule id.
const maxIDBytes = 64

// maxMinEntropy is the largest meaningful entropy in bits per byte.
const maxMinEntropy = 8

// RuleConfig describes one team rule in a configuration.
type RuleConfig struct {
	// ID is the rule identifier: 1 to 64 characters from A-Z a-z 0-9 . _ -
	ID string `json:"id"`

	// Description is a short human-readable name.
	Description string `json:"description,omitempty"`

	// Pattern is an RE2 expression of at most 1000 bytes.
	Pattern string `json:"pattern"`

	// SecretGroup is the capture group holding the secret; 0 means the whole match.
	SecretGroup int `json:"secretGroup,omitempty"`

	// MinEntropy is the minimum Shannon entropy of the secret in bits per byte.
	MinEntropy float64 `json:"minEntropy,omitempty"`
}

// Config is the scanner configuration, usually loaded with [LoadConfig].
type Config struct {
	// Rules are team rules added to the built-in ones.
	Rules []RuleConfig `json:"rules,omitempty"`

	// DisableDefaults turns the ten built-in rules off.
	DisableDefaults bool `json:"disableDefaults,omitempty"`

	// Allowlist suppresses findings.
	Allowlist struct {
		// Paths are path.Match globs tested against the slash-separated path
		// and against its base name; a match skips the whole file.
		Paths []string `json:"paths,omitempty"`

		// Regexes are RE2 expressions tested against the captured secret; a
		// match suppresses that finding.
		Regexes []string `json:"regexes,omitempty"`
	} `json:"allowlist"`
}

// LoadConfig reads a JSON configuration of at most [MaxConfigSize] bytes,
// rejects unknown fields and trailing data, and validates every rule and
// allowlist entry. Errors match [ErrInvalidConfig] and name the rule id where
// one applies.
func LoadConfig(r io.Reader) (Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxConfigSize+1))
	if err != nil {
		return Config{}, readError("config", err)
	}
	if len(data) > MaxConfigSize {
		return Config{}, invalidf("config exceeds %d bytes", MaxConfigSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, invalidf("invalid JSON: %s", truncate(err.Error()))
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, invalidf("unexpected data after the config object")
	}
	if _, err := compileConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// scanRule is a rule prepared for scanning.
type scanRule struct {
	Rule

	// anchored is true when the pattern uses the token word-boundary wrapper.
	anchored bool
}

// compiled is a validated configuration.
type compiled struct {
	rules        []scanRule
	allowPaths   []string
	allowRegexes []*regexp.Regexp
}

// validID reports whether id is a legal rule identifier.
func validID(id string) bool {
	if id == "" || len(id) > maxIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// buildRule validates and compiles one team rule.
func buildRule(index int, rc RuleConfig) (Rule, error) {
	if !validID(rc.ID) {
		return Rule{}, invalidf("rule #%d: invalid id (use 1-%d characters from A-Z a-z 0-9 . _ -)", index, maxIDBytes)
	}
	if rc.Pattern == "" {
		return Rule{}, invalidf("rule %q: empty pattern", rc.ID)
	}
	if len(rc.Pattern) > MaxPatternBytes {
		return Rule{}, invalidf("rule %q: pattern exceeds %d bytes", rc.ID, MaxPatternBytes)
	}
	re, err := regexp.Compile(rc.Pattern)
	if err != nil {
		return Rule{}, invalidf("rule %q: invalid pattern: %s", rc.ID, truncate(err.Error()))
	}
	if rc.SecretGroup < 0 || rc.SecretGroup > re.NumSubexp() {
		return Rule{}, invalidf("rule %q: secretGroup %d is out of range", rc.ID, rc.SecretGroup)
	}
	if math.IsNaN(rc.MinEntropy) || rc.MinEntropy < 0 || rc.MinEntropy > maxMinEntropy {
		return Rule{}, invalidf("rule %q: minEntropy must be between 0 and %d", rc.ID, maxMinEntropy)
	}
	return Rule{ID: rc.ID, Description: rc.Description, Pattern: re, SecretGroup: rc.SecretGroup, MinEntropy: rc.MinEntropy}, nil
}

// compileConfig validates cfg and prepares it for scanning.
func compileConfig(cfg Config) (compiled, error) {
	var out compiled
	if len(cfg.Rules) > MaxRules {
		return out, invalidf("too many rules: %d (max %d)", len(cfg.Rules), MaxRules)
	}
	var rules []Rule
	if !cfg.DisableDefaults {
		rules = DefaultRules()
	}
	seen := make(map[string]bool, len(rules)+len(cfg.Rules))
	for _, r := range rules {
		seen[r.ID] = true
	}
	for i, rc := range cfg.Rules {
		r, err := buildRule(i, rc)
		if err != nil {
			return out, err
		}
		if seen[r.ID] {
			return out, invalidf("rule %q: duplicate id", r.ID)
		}
		seen[r.ID] = true
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return out, invalidf("no rules enabled")
	}
	for _, r := range rules {
		anchored := strings.HasPrefix(r.Pattern.String(), wrapPrefix)
		out.rules = append(out.rules, scanRule{Rule: r, anchored: anchored})
	}
	if len(cfg.Allowlist.Paths) > MaxRules || len(cfg.Allowlist.Regexes) > MaxRules {
		return out, invalidf("too many allowlist entries (max %d per list)", MaxRules)
	}
	for i, glob := range cfg.Allowlist.Paths {
		if glob == "" || len(glob) > MaxPatternBytes {
			return out, invalidf("allowlist path #%d is empty or exceeds %d bytes", i, MaxPatternBytes)
		}
		if _, err := path.Match(glob, ""); err != nil {
			return out, invalidf("allowlist path #%d: invalid glob", i)
		}
		out.allowPaths = append(out.allowPaths, glob)
	}
	for i, expr := range cfg.Allowlist.Regexes {
		if expr == "" || len(expr) > MaxPatternBytes {
			return out, invalidf("allowlist regex #%d is empty or exceeds %d bytes", i, MaxPatternBytes)
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return out, invalidf("allowlist regex #%d: %s", i, truncate(err.Error()))
		}
		out.allowRegexes = append(out.allowRegexes, re)
	}
	return out, nil
}
