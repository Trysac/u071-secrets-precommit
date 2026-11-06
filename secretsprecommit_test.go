package secretsprecommit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	secretsprecommit "github.com/Trysac/u071-secrets-precommit"
)

const nl = "\n"

const crlf = "\r\n"

// awsKey builds a fake AWS access key id at runtime.
func awsKey() string {
	return "AK" + "IA" + strings.Repeat("A7", 8)
}

// ghToken builds a fake GitHub token at runtime.
func ghToken() string {
	return "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
}

func newScanner(t *testing.T, cfg secretsprecommit.Config, events *[]secretsprecommit.Event) *secretsprecommit.Scanner {
	t.Helper()
	var opts secretsprecommit.Options
	if events != nil {
		opts.OnEvent = func(e secretsprecommit.Event) {
			*events = append(*events, e)
		}
	}
	s, err := secretsprecommit.NewScanner(cfg, opts)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	return s
}

func scanText(t *testing.T, s *secretsprecommit.Scanner, name, text string) []secretsprecommit.Finding {
	t.Helper()
	got, err := s.ScanReader(name, strings.NewReader(text))
	if err != nil {
		t.Fatalf("ScanReader(%q): %v", name, err)
	}
	return got
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func pad(head string, size int) []byte {
	b := make([]byte, 0, size+1)
	b = append(b, head...)
	for len(b) < size {
		b = append(b, 'a')
	}
	return b
}

func ruleIDs(list []secretsprecommit.Finding) []string {
	ids := make([]string, 0, len(list))
	for _, f := range list {
		ids = append(ids, f.RuleID)
	}
	return ids
}

type sample struct{ rule, line, secret string }

func tokenSample(rule, secret string) sample {
	return sample{rule, "v: " + secret, secret}
}

func samples() []sample {
	generic := "q7Zp2Lk9Xw4Rb8Nv"
	fine := "github" + "_pat_" + strings.Repeat("aB3_", 20) + "aB"
	slack := "xo" + "xb-" + "1234567890-abcdefghij"
	stripe := "sk" + "_live_" + strings.Repeat("aZ9", 8)
	google := "AI" + "za" + strings.Repeat("aB3-_", 7)
	anthropic := "sk-ant-" + "api03-" + strings.Repeat("aB3-_", 18) + "aB3" + "AA"
	openai := "sk-" + strings.Repeat("aB3", 7) + "T3Blbk" + "FJ" + strings.Repeat("xY9", 7)
	pem := "-----BEGIN " + "RSA PRIVATE KEY-----"
	return []sample{
		tokenSample("aws-access-key-id", awsKey()),
		tokenSample("github-token", ghToken()),
		tokenSample("github-fine-grained-pat", fine),
		tokenSample("slack-token", slack),
		tokenSample("stripe-live-key", stripe),
		tokenSample("google-api-key", google),
		tokenSample("anthropic-api-key", anthropic),
		tokenSample("openai-api-key", openai),
		tokenSample("private-key-block", pem),
		{"generic-assignment", fmt.Sprintf("password = %q", generic), generic},
	}
}

func TestAWSKeyLineAndColumn(t *testing.T) {
	s := newScanner(t, secretsprecommit.Config{}, nil)
	text := "first line" + nl + "second line" + nl + "aws_id: " + awsKey() + nl
	got := scanText(t, s, "a.txt", text)
	want := secretsprecommit.Finding{RuleID: "aws-access-key-id", Path: "a.txt", Line: 3, Column: 9, Redacted: "AKIA****"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("findings = %+v, want [%+v]", got, want)
	}
	if line := got[0].String(); line != "a.txt:3:9: aws-access-key-id: AKIA****" {
		t.Fatalf("String() = %q", line)
	}
}

func TestEverySampleDetectedAndNeverLeaked(t *testing.T) {
	all := samples()
	if len(all) != len(secretsprecommit.DefaultRules()) {
		t.Fatalf("%d samples for %d default rules", len(all), len(secretsprecommit.DefaultRules()))
	}
	for _, sm := range all {
		t.Run(sm.rule, func(t *testing.T) {
			var events []secretsprecommit.Event
			s := newScanner(t, secretsprecommit.Config{}, &events)
			got := scanText(t, s, "src/app.txt", sm.line)
			if !slices.Contains(ruleIDs(got), sm.rule) {
				t.Fatalf("rule %s did not fire; got %v", sm.rule, ruleIDs(got))
			}
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			outputs := []string{string(data)}
			for _, f := range got {
				outputs = append(outputs, f.String())
				if len(f.Redacted) != 8 || !strings.HasSuffix(f.Redacted, "****") {
					t.Fatalf("Redacted %q does not have 4 visible characters plus ****", f.Redacted)
				}
			}
			for _, e := range events {
				outputs = append(outputs, fmt.Sprintf("%+v", e))
			}
			for _, o := range outputs {
				if strings.Contains(o, sm.secret) {
					t.Fatal("an output contains the full secret")
				}
			}
		})
	}
}

func TestGenericAssignment(t *testing.T) {
	s := newScanner(t, secretsprecommit.Config{}, nil)
	value := "q7Zp2Lk9Xw4Rb8Nv"
	cases := []struct {
		name string
		text string
		want int
	}{
		{"double quoted 16 characters", fmt.Sprintf("password = %q", value), 1},
		{"upper case keyword", fmt.Sprintf("PASSWORD = %q", value), 1},
		{"single quotes and colon", "token: '" + value + "'", 1},
		{"low entropy", `password = "aaaaaaaaaaaa"`, 0},
		{"too short", `password = "q7Zp2Lk9Xw4"`, 0},
		{"unquoted", "password = " + value, 0},
		{"allow marker on the line", fmt.Sprintf("password = %q # secrets-precommit:allow", value), 0},
		{"allow marker beats a token rule", "secrets-precommit:allow " + awsKey(), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanText(t, s, "f.txt", tc.text); len(got) != tc.want {
				t.Fatalf("findings = %v, want %d", ruleIDs(got), tc.want)
			}
		})
	}
}

func TestAllowlists(t *testing.T) {
	var cfg secretsprecommit.Config
	cfg.Allowlist.Paths = []string{"*.md", "testdata/*"}
	cfg.Allowlist.Regexes = []string{"^q7Zp"}
	var events []secretsprecommit.Event
	s := newScanner(t, cfg, &events)
	line := "k: " + awsKey()
	if got := scanText(t, s, "docs/readme.md", line); len(got) != 0 {
		t.Fatalf("base-name glob did not apply: %v", got)
	}
	if got := scanText(t, s, "testdata/a.txt", line); len(got) != 0 {
		t.Fatalf("path glob did not apply: %v", got)
	}
	if got := scanText(t, s, "testdata/x/a.txt", line); len(got) != 1 {
		t.Fatalf("glob must not cross directories: %v", got)
	}
	if got := scanText(t, s, "src/a.txt", line); len(got) != 1 {
		t.Fatalf("unlisted path must be scanned: %v", got)
	}
	suppressed := fmt.Sprintf("password = %q", "q7Zp2Lk9Xw4Rb8Nv")
	if got := scanText(t, s, "src/b.txt", suppressed); len(got) != 0 {
		t.Fatalf("allowlist regex did not apply: %v", got)
	}
	kept := fmt.Sprintf("password = %q", "z7Zp2Lk9Xw4Rb8Nv")
	if got := scanText(t, s, "src/b.txt", kept); len(got) != 1 {
		t.Fatalf("non-matching value must be reported: %v", got)
	}
	want := secretsprecommit.Event{Kind: secretsprecommit.EventSkip, Path: "docs/readme.md", Reason: "allowlisted"}
	if !slices.Contains(events, want) {
		t.Fatalf("missing allowlisted skip event in %v", events)
	}
}

func TestTokenBoundaries(t *testing.T) {
	s := newScanner(t, secretsprecommit.Config{}, nil)
	tok := ghToken()
	cases := []struct {
		name string
		text string
		cols []int
	}{
		{"followed by quote and comma", `x = "` + tok + `",`, []int{6}},
		{"after url query", "https://x/?t=" + tok, []int{14}},
		{"extra trailing word char", tok + "a", nil},
		{"extra leading word char", "a" + tok, nil},
		{"trailing digit", tok + "9", nil},
		{"trailing underscore", tok + "_", nil},
		{"leading underscore", "_" + tok, nil},
		{"trailing hyphen", tok + "-", []int{1}},
		{"trailing dot", tok + ".", []int{1}},
		{"two tokens one space apart", tok + " " + tok, []int{1, 42}},
		{"two tokens one comma apart", tok + "," + tok, []int{1, 42}},
		{"multibyte prefix counts runes", "é€ " + awsKey(), []int{4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cols []int
			for _, f := range scanText(t, s, "f.txt", tc.text) {
				cols = append(cols, f.Column)
			}
			if !slices.Equal(cols, tc.cols) {
				t.Fatalf("columns = %v, want %v", cols, tc.cols)
			}
		})
	}
}

func TestTokenAlsoMatchedByGenericReportedOncePerRule(t *testing.T) {
	s := newScanner(t, secretsprecommit.Config{}, nil)
	text := `token = "` + ghToken() + `"`
	got := scanText(t, s, "f.txt", text)
	if len(got) != 2 {
		t.Fatalf("findings = %v, want two", got)
	}
	if got[0].RuleID != "generic-assignment" || got[1].RuleID != "github-token" {
		t.Fatalf("rules = %v", ruleIDs(got))
	}
	if got[0].Column != 10 || got[1].Column != 10 {
		t.Fatalf("columns = %d, %d", got[0].Column, got[1].Column)
	}
}

func TestFindingEventsCarryNoSecret(t *testing.T) {
	var events []secretsprecommit.Event
	s := newScanner(t, secretsprecommit.Config{}, &events)
	text := "k: " + awsKey()
	scanText(t, s, "a.txt", text)
	want := secretsprecommit.Event{Kind: secretsprecommit.EventFinding, Path: "a.txt", RuleID: "aws-access-key-id"}
	if len(events) != 1 || events[0] != want {
		t.Fatalf("events = %+v, want [%+v]", events, want)
	}
}

func TestBinaryAndTooLargeFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	tok := ghToken()
	binBody := []byte("x " + tok + nl)
	binBody = append(binBody, 0, 'z')
	binary := writeFile(t, dir, "bin.dat", binBody)
	huge := bytes.Repeat([]byte("a"), secretsprecommit.MaxFileSize+1)
	large := writeFile(t, dir, "big.txt", huge)
	var events []secretsprecommit.Event
	s := newScanner(t, secretsprecommit.Config{}, &events)
	got, err := s.ScanFiles([]string{binary, large})
	if err != nil || len(got) != 0 {
		t.Fatalf("findings = %v, err = %v", got, err)
	}
	want := []secretsprecommit.Event{
		{Kind: secretsprecommit.EventSkip, Path: binary, Reason: "binary"},
		{Kind: secretsprecommit.EventSkip, Path: large, Reason: "too_large"},
	}
	if !slices.Equal(events, want) {
		t.Fatalf("events = %+v, want %+v", events, want)
	}
}

func TestSymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	target := writeFile(t, dir, "real.txt", []byte("x "+ghToken()+nl))
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var events []secretsprecommit.Event
	s := newScanner(t, secretsprecommit.Config{}, &events)
	got, err := s.ScanFiles([]string{link})
	if err != nil || len(got) != 0 {
		t.Fatalf("findings = %v, err = %v", got, err)
	}
	want := secretsprecommit.Event{Kind: secretsprecommit.EventSkip, Path: link, Reason: "symlink"}
	if len(events) != 1 || events[0] != want {
		t.Fatalf("events = %+v, want [%+v]", events, want)
	}
}

func TestDirectorySkipped(t *testing.T) {
	dir := t.TempDir()
	var events []secretsprecommit.Event
	s := newScanner(t, secretsprecommit.Config{}, &events)
	if _, err := s.ScanFiles([]string{dir}); err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(events) != 1 || events[0].Reason != "directory" {
		t.Fatalf("events = %+v", events)
	}
}

func TestPathAllowlistSkipsFilesWithoutOpening(t *testing.T) {
	dir := t.TempDir()
	body := []byte("k: " + awsKey() + nl)
	file := writeFile(t, dir, "keep.md", body)
	var cfg secretsprecommit.Config
	cfg.Allowlist.Paths = []string{"*.md"}
	var events []secretsprecommit.Event
	s := newScanner(t, cfg, &events)
	got, err := s.ScanFiles([]string{file})
	if err != nil || len(got) != 0 {
		t.Fatalf("findings = %v, err = %v", got, err)
	}
	if len(events) != 1 || events[0].Reason != "allowlisted" {
		t.Fatalf("events = %+v", events)
	}
}

func TestSizeAndSniffBoundaries(t *testing.T) {
	head := "x " + ghToken() + nl
	cases := []struct {
		name string
		data []byte
		want int
		skip string
	}{
		{"exactly the maximum size", pad(head, secretsprecommit.MaxFileSize), 1, ""},
		{"one byte over the maximum", bytes.Repeat([]byte("a"), secretsprecommit.MaxFileSize+1), 0, "too_large"},
		{"NUL just after the sniff window", append(pad(head, 8192), 0), 1, ""},
		{"NUL at the last sniffed byte", append(pad(head, 8191), 0), 0, "binary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var events []secretsprecommit.Event
			s := newScanner(t, secretsprecommit.Config{}, &events)
			got, err := s.ScanReader("f.bin", bytes.NewReader(tc.data))
			if err != nil {
				t.Fatalf("ScanReader: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("findings = %d, want %d", len(got), tc.want)
			}
			var reasons []string
			for _, e := range events {
				if e.Kind == secretsprecommit.EventSkip {
					reasons = append(reasons, e.Reason)
				}
			}
			var wantReasons []string
			if tc.skip != "" {
				wantReasons = []string{tc.skip}
			}
			if !slices.Equal(reasons, wantReasons) {
				t.Fatalf("skip reasons = %v, want %v", reasons, wantReasons)
			}
		})
	}
}

func TestCRLFColumnsMatchLF(t *testing.T) {
	s := newScanner(t, secretsprecommit.Config{}, nil)
	lines := []string{"one", "k: " + awsKey(), "two " + ghToken()}
	lf := scanText(t, s, "f.txt", strings.Join(lines, nl)+nl)
	crlfGot := scanText(t, s, "f.txt", strings.Join(lines, crlf)+crlf)
	if len(lf) != 2 || !slices.Equal(lf, crlfGot) {
		t.Fatalf("LF = %+v, CRLF = %+v", lf, crlfGot)
	}
}

func TestScanFilesSortedAndContinuesAfterError(t *testing.T) {
	dir := t.TempDir()
	bodyA := []byte("k: " + awsKey() + nl)
	bodyB := []byte("x " + ghToken() + " " + awsKey() + nl)
	a := writeFile(t, dir, "a.txt", bodyA)
	b := writeFile(t, dir, "b.txt", bodyB)
	missing := filepath.Join(dir, "missing.txt")
	s := newScanner(t, secretsprecommit.Config{}, nil)
	got, err := s.ScanFiles([]string{b, missing, a})
	if !errors.Is(err, secretsprecommit.ErrRead) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want ErrRead wrapping fs.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), "missing.txt") {
		t.Fatalf("error does not name the path: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("findings = %+v", got)
	}
	if got[0].Path != a || got[0].Column != 4 {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].Path != b || got[1].Column != 3 || got[1].RuleID != "github-token" {
		t.Fatalf("second = %+v", got[1])
	}
	if got[2].Path != b || got[2].Column != 44 || got[2].RuleID != "aws-access-key-id" {
		t.Fatalf("third = %+v", got[2])
	}
}

func TestScanFilesEmptyList(t *testing.T) {
	s := newScanner(t, secretsprecommit.Config{}, nil)
	got, err := s.ScanFiles(nil)
	if got != nil || err != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestScanReaderReadError(t *testing.T) {
	s := newScanner(t, secretsprecommit.Config{}, nil)
	_, err := s.ScanReader("p.txt", iotest.ErrReader(errors.New("boom")))
	if !errors.Is(err, secretsprecommit.ErrRead) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "p.txt") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("message = %q", err.Error())
	}
	var e *secretsprecommit.Error
	if !errors.As(err, &e) || e.Code != secretsprecommit.CodeRead {
		t.Fatalf("error type/code wrong: %v", err)
	}
}

func TestLoadConfigRejects(t *testing.T) {
	oversize := `{"rules":[]}` + strings.Repeat(" ", secretsprecommit.MaxConfigSize)
	cases := []struct {
		name, body, note string
	}{
		{"invalid regex", `{"rules":[{"id":"bad-rule","pattern":"("}]}`, "bad-rule"},
		{"unknown field", `{"nope":true}`, "unknown field"},
		{"unknown rule field", `{"rules":[{"id":"a","pattern":"x","zzz":1}]}`, "unknown field"},
		{"over one MiB", oversize, "exceeds"},
		{"wrong type", `{"rules":"x"}`, "invalid JSON"},
		{"empty input", ``, "invalid JSON"},
		{"trailing object", `{} {}`, "unexpected data"},
		{"trailing garbage", `{}x`, "unexpected data"},
		{"bad id", `{"rules":[{"id":"bad id","pattern":"a"}]}`, "invalid id"},
		{"empty id", `{"rules":[{"id":"","pattern":"a"}]}`, "invalid id"},
		{"empty pattern", `{"rules":[{"id":"p1","pattern":""}]}`, "p1"},
		{"group out of range", `{"rules":[{"id":"g1","pattern":"(a)","secretGroup":2}]}`, "g1"},
		{"negative group", `{"rules":[{"id":"g2","pattern":"(a)","secretGroup":-1}]}`, "g2"},
		{"negative entropy", `{"rules":[{"id":"e1","pattern":"a","minEntropy":-1}]}`, "e1"},
		{"entropy too large", `{"rules":[{"id":"e2","pattern":"a","minEntropy":9}]}`, "e2"},
		{"duplicate team ids", `{"rules":[{"id":"d1","pattern":"a"},{"id":"d1","pattern":"b"}]}`, "d1"},
		{"duplicate default id", `{"rules":[{"id":"github-token","pattern":"a"}]}`, "github-token"},
		{"no rules", `{"disableDefaults":true}`, "no rules"},
		{"bad glob", `{"allowlist":{"paths":["["]}}`, "allowlist path"},
		{"empty glob", `{"allowlist":{"paths":[""]}}`, "allowlist path"},
		{"bad allowlist regex", `{"allowlist":{"regexes":["("]}}`, "allowlist regex"},
		{"empty allowlist regex", `{"allowlist":{"regexes":[""]}}`, "allowlist regex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := secretsprecommit.LoadConfig(strings.NewReader(tc.body))
			if !errors.Is(err, secretsprecommit.ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
			if !strings.Contains(err.Error(), tc.note) {
				t.Fatalf("message %q does not contain %q", err.Error(), tc.note)
			}
		})
	}
}

func TestLoadConfigReadError(t *testing.T) {
	_, err := secretsprecommit.LoadConfig(iotest.ErrReader(errors.New("boom")))
	if !errors.Is(err, secretsprecommit.ErrRead) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadConfigValid(t *testing.T) {
	body := `{"rules":[{"id":"corp-token","description":"Corp","pattern":"corp_[a-z0-9]{8}"}],"allowlist":{"paths":["*.md"],"regexes":["^dummy"]}}`
	cfg, err := secretsprecommit.LoadConfig(strings.NewReader(body))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Allowlist.Paths[0] != "*.md" || cfg.Allowlist.Regexes[0] != "^dummy" {
		t.Fatalf("cfg = %+v", cfg)
	}
	s := newScanner(t, cfg, nil)
	got := scanText(t, s, "f.txt", "x corp_abcd1234")
	want := secretsprecommit.Finding{RuleID: "corp-token", Path: "f.txt", Line: 1, Column: 3, Redacted: "corp****"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %+v, want [%+v]", got, want)
	}
	if got := scanText(t, s, "notes.md", "x corp_abcd1234"); len(got) != 0 {
		t.Fatalf("allowlisted path reported: %v", got)
	}
	empty, err := secretsprecommit.LoadConfig(strings.NewReader(`{}`))
	if err != nil || len(empty.Rules) != 0 {
		t.Fatalf("empty config: %+v, %v", empty, err)
	}
}

func wantInvalid(t *testing.T, cfg secretsprecommit.Config, note string) {
	t.Helper()
	_, err := secretsprecommit.NewScanner(cfg, secretsprecommit.Options{})
	if !errors.Is(err, secretsprecommit.ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), note) {
		t.Fatalf("message %q does not contain %q", err.Error(), note)
	}
}

func TestNewScannerLimits(t *testing.T) {
	many := make([]secretsprecommit.RuleConfig, secretsprecommit.MaxRules+1)
	for i := range many {
		many[i] = secretsprecommit.RuleConfig{ID: fmt.Sprintf("r%d", i), Pattern: "x"}
	}
	wantInvalid(t, secretsprecommit.Config{Rules: many}, "too many rules")

	longPattern := strings.Repeat("a", secretsprecommit.MaxPatternBytes+1)
	longRule := secretsprecommit.RuleConfig{ID: "long", Pattern: longPattern}
	wantInvalid(t, secretsprecommit.Config{Rules: []secretsprecommit.RuleConfig{longRule}}, "long")

	nanRule := secretsprecommit.RuleConfig{ID: "nan", Pattern: "a", MinEntropy: math.NaN()}
	wantInvalid(t, secretsprecommit.Config{Rules: []secretsprecommit.RuleConfig{nanRule}}, "nan")

	var tooManyPaths secretsprecommit.Config
	tooManyPaths.Allowlist.Paths = make([]string, secretsprecommit.MaxRules+1)
	wantInvalid(t, tooManyPaths, "too many allowlist")

	var longGlob secretsprecommit.Config
	longGlob.Allowlist.Paths = []string{longPattern}
	wantInvalid(t, longGlob, "exceeds")

	var longRegex secretsprecommit.Config
	longRegex.Allowlist.Regexes = []string{longPattern}
	wantInvalid(t, longRegex, "exceeds")

	wantInvalid(t, secretsprecommit.Config{DisableDefaults: true}, "no rules")
}

func TestErrorMessagesAreBounded(t *testing.T) {
	rule := secretsprecommit.RuleConfig{ID: "deep", Pattern: strings.Repeat("(", 900)}
	_, err := secretsprecommit.NewScanner(secretsprecommit.Config{Rules: []secretsprecommit.RuleConfig{rule}}, secretsprecommit.Options{})
	if !errors.Is(err, secretsprecommit.ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, strings.Repeat("(", 201)) || len(msg) >= 400 {
		t.Fatalf("message too long (%d bytes)", len(msg))
	}
	var e *secretsprecommit.Error
	if !errors.As(err, &e) || e.Code != secretsprecommit.CodeInvalidConfig {
		t.Fatalf("error type/code wrong: %v", err)
	}
}

func TestTeamRules(t *testing.T) {
	esc := string(rune(0x1b))
	cfg := secretsprecommit.Config{DisableDefaults: true}
	cfg.Rules = []secretsprecommit.RuleConfig{
		{ID: "corp-token", Pattern: `corp_[a-z0-9]{8}`},
		{ID: "pw-entropy", Pattern: `pw=(\w+)`, SecretGroup: 1, MinEntropy: 2},
		{ID: "pin-code", Pattern: `pin=(\d+)`, SecretGroup: 1},
		{ID: "ctrl-code", Pattern: `X(\x1b[a-z]{6})`, SecretGroup: 1},
	}
	s := newScanner(t, cfg, nil)
	cases := []struct {
		name string
		text string
		want []secretsprecommit.Finding
	}{
		{"whole match", "x corp_abcd1234", []secretsprecommit.Finding{{RuleID: "corp-token", Path: "f.txt", Line: 1, Column: 3, Redacted: "corp****"}}},
		{"low entropy rejected", "pw=aaaaaa", nil},
		{"entropy accepted", "pw=abcdefghij", []secretsprecommit.Finding{{RuleID: "pw-entropy", Path: "f.txt", Line: 1, Column: 4, Redacted: "abcd****"}}},
		{"short secret shows fewer runes", "pin=1234", []secretsprecommit.Finding{{RuleID: "pin-code", Path: "f.txt", Line: 1, Column: 5, Redacted: "12****"}}},
		{"adjacent matches", "pin=1234 pin=5678", []secretsprecommit.Finding{
			{RuleID: "pin-code", Path: "f.txt", Line: 1, Column: 5, Redacted: "12****"},
			{RuleID: "pin-code", Path: "f.txt", Line: 1, Column: 14, Redacted: "56****"},
		}},
		{"control runes replaced", "X" + esc + "abcdef", []secretsprecommit.Finding{{RuleID: "ctrl-code", Path: "f.txt", Line: 1, Column: 2, Redacted: "?ab****"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanText(t, s, "f.txt", tc.text)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPathologicalInputsStayLinear(t *testing.T) {
	cfg := secretsprecommit.Config{}
	cfg.Rules = []secretsprecommit.RuleConfig{{ID: "evil", Pattern: `(a+)+$`}}
	s := newScanner(t, cfg, nil)
	long := strings.Repeat("a", 1<<18) + "!"
	if got := scanText(t, s, "f.txt", long); len(got) != 0 {
		t.Fatalf("unexpected findings on pathological line: %d", len(got))
	}
	glued := strings.Repeat("AKIAA7", 1<<15)
	if got := scanText(t, s, "f.txt", glued); len(got) != 0 {
		t.Fatalf("glued tokens must not be reported: %d", len(got))
	}
	many := strings.Repeat(awsKey()+" ", 2000)
	if got := scanText(t, s, "f.txt", many); len(got) != 2000 {
		t.Fatalf("findings = %d, want 2000", len(got))
	}
}

func TestDefaultRules(t *testing.T) {
	rules := secretsprecommit.DefaultRules()
	wantIDs := []string{"aws-access-key-id", "github-token", "github-fine-grained-pat", "slack-token", "stripe-live-key", "google-api-key", "anthropic-api-key", "openai-api-key", "private-key-block", "generic-assignment"}
	var ids []string
	for _, r := range rules {
		ids = append(ids, r.ID)
		if r.Pattern == nil || r.Description == "" || r.SecretGroup != 1 {
			t.Fatalf("rule %s is incomplete: %+v", r.ID, r)
		}
		wantEntropy := 0.0
		if r.ID == "generic-assignment" {
			wantEntropy = 3.5
		}
		if r.MinEntropy != wantEntropy {
			t.Fatalf("rule %s MinEntropy = %v", r.ID, r.MinEntropy)
		}
	}
	if !slices.Equal(ids, wantIDs) {
		t.Fatalf("ids = %v", ids)
	}
	if !strings.Contains(rules[1].Pattern.String(), `gh[pousr]_[A-Za-z0-9]{36}`) {
		t.Fatalf("github pattern = %s", rules[1].Pattern)
	}
	if !strings.Contains(rules[9].Pattern.String(), `[:=]`) {
		t.Fatalf("generic pattern = %s", rules[9].Pattern)
	}
	rules[0].ID = "mutated"
	if again := secretsprecommit.DefaultRules(); again[0].ID != "aws-access-key-id" {
		t.Fatal("DefaultRules shares state between calls")
	}
}

func TestFindingJSONAndString(t *testing.T) {
	f := secretsprecommit.Finding{RuleID: "aws-access-key-id", Path: "a.txt", Line: 3, Column: 9, Redacted: "AKIA****"}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"ruleId":"aws-access-key-id","path":"a.txt","line":3,"column":9,"redacted":"AKIA****"}`
	if string(data) != want {
		t.Fatalf("json = %s", data)
	}
	esc := string(rune(0x1b))
	f.Path = "a" + esc + "[31m.txt"
	if strings.ContainsRune(f.String(), 0x1b) {
		t.Fatal("String() leaks a raw control character")
	}
}

func TestNoRulesRejected(t *testing.T) {
	_, err := secretsprecommit.NewScanner(secretsprecommit.Config{DisableDefaults: true}, secretsprecommit.Options{})
	if !errors.Is(err, secretsprecommit.ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}

func ExampleScanner_ScanReader() {
	s, _ := secretsprecommit.NewScanner(secretsprecommit.Config{}, secretsprecommit.Options{})
	text := "one" + nl + "two" + nl + "aws_id: " + awsKey() + nl
	findings, _ := s.ScanReader("a.txt", strings.NewReader(text))
	for _, f := range findings {
		fmt.Println(f)
	}
	// Output:
	// a.txt:3:9: aws-access-key-id: AKIA****
}
