package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secretsprecommit "github.com/Trysac/u071-secrets-precommit"
)

const nl = "\n"

const crlf = "\r\n"

func awsKey() string {
	return "AK" + "IA" + strings.Repeat("A7", 8)
}

func ghToken() string {
	return "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	clean := writeFile(t, dir, "clean.txt", "nothing to see")
	dirtyBody := "k: " + awsKey() + nl
	dirty := writeFile(t, dir, "dirty.txt", dirtyBody)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no findings", []string{clean}, 0},
		{"findings", []string{dirty}, 1},
		{"no file arguments", nil, 2},
		{"unknown flag", []string{"--bogus", clean}, 2},
		{"unknown format", []string{"--format", "xml", clean}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, _ := run(t, tc.args...); code != tc.want {
				t.Fatalf("exit code = %d, want %d", code, tc.want)
			}
		})
	}
}

func TestRunNoArgumentsPrintsUsage(t *testing.T) {
	code, out, errOut := run(t)
	if code != 2 || out != "" || !strings.Contains(errOut, "usage") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, out, errOut)
	}
}

func TestRunTextLineForA(t *testing.T) {
	dir := t.TempDir()
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldDir) })
	content := "first" + nl + "second" + nl + "aws_id: " + awsKey() + nl
	if err := os.WriteFile("a.txt", []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	code, out, _ := run(t, "a.txt")
	want := "a.txt:3:9: aws-access-key-id: AKIA****" + nl
	if code != 1 || out != want {
		t.Fatalf("code = %d, stdout = %q, want %q", code, out, want)
	}
}

func TestRunJSON(t *testing.T) {
	dir := t.TempDir()
	body := "first" + nl + "second" + nl + "aws_id: " + awsKey() + nl
	file := writeFile(t, dir, "a.txt", body)
	code, out, _ := run(t, "--format", "json", file)
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	var got []secretsprecommit.Finding
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	want := secretsprecommit.Finding{RuleID: "aws-access-key-id", Path: file, Line: 3, Column: 9, Redacted: "AKIA****"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %+v, want [%+v]", got, want)
	}
}

func TestRunJSONWithoutFindingsIsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	file := writeFile(t, dir, "clean.txt", "nothing")
	code, out, _ := run(t, "--format", "json", file)
	if code != 0 || out != "[]"+nl {
		t.Fatalf("code = %d, stdout = %q", code, out)
	}
}

func TestRunNeverPrintsSecrets(t *testing.T) {
	dir := t.TempDir()
	for _, secret := range []string{awsKey(), ghToken()} {
		body := "k: " + secret + nl
		file := writeFile(t, dir, "s.txt", body)
		for _, format := range []string{"text", "json"} {
			code, out, errOut := run(t, "--format", format, file)
			combined := out + errOut
			if code != 1 || strings.Contains(combined, secret) {
				t.Fatalf("format %s: code = %d or output contains the secret", format, code)
			}
		}
	}
}

func TestRunConfigAndNoDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "cfg.json", `{"rules":[{"id":"corp-token","pattern":"corp_[a-z0-9]{8}"}]}`)
	body := "x corp_abcd1234" + nl + "k: " + awsKey() + nl
	file := writeFile(t, dir, "f.txt", body)
	code, out, _ := run(t, "--config", cfgPath, file)
	if code != 1 || !strings.Contains(out, "corp-token") || !strings.Contains(out, "aws-access-key-id") {
		t.Fatalf("code = %d, stdout = %q", code, out)
	}
	code, out, _ = run(t, "--config", cfgPath, "--no-defaults", file)
	if code != 1 || !strings.Contains(out, "corp-token") || strings.Contains(out, "aws-access-key-id") {
		t.Fatalf("--no-defaults: code = %d, stdout = %q", code, out)
	}
	awsOnly := writeFile(t, dir, "aws.txt", "k: "+awsKey()+nl)
	if code, _, _ := run(t, "--config", cfgPath, "--no-defaults", awsOnly); code != 0 {
		t.Fatalf("built-in rule fired despite --no-defaults: %d", code)
	}
	code, _, errOut := run(t, "--no-defaults", file)
	if code != 2 || !strings.Contains(errOut, "no rules") {
		t.Fatalf("no rules: code = %d, stderr = %q", code, errOut)
	}
}

func TestRunConfigErrors(t *testing.T) {
	dir := t.TempDir()
	target := writeFile(t, dir, "t.txt", "nothing")
	padding := strings.Repeat(" ", 1<<20)
	oversize := "{}" + padding
	cases := []struct {
		name string
		body string
		want string
	}{
		{"invalid regex", `{"rules":[{"id":"bad-rule","pattern":"("}]}`, "bad-rule"},
		{"unknown field", `{"nope":true}`, "unknown field"},
		{"over one MiB", oversize, "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := writeFile(t, dir, "cfg.json", tc.body)
			code, _, errOut := run(t, "--config", cfgPath, target)
			if code != 2 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("code = %d, stderr = %q", code, errOut)
			}
		})
	}
	missing := filepath.Join(dir, "missing.json")
	if code, _, _ := run(t, "--config", missing, target); code != 2 {
		t.Fatalf("missing config: code = %d", code)
	}
}

func TestRunSortsByPathLineColumn(t *testing.T) {
	dir := t.TempDir()
	bodyA := "k: " + awsKey() + nl
	bodyB := "x " + ghToken() + nl
	a := writeFile(t, dir, "a.txt", bodyA)
	b := writeFile(t, dir, "b.txt", bodyB)
	code, out, _ := run(t, b, a)
	lines := strings.Split(strings.TrimSpace(out), nl)
	if code != 1 || len(lines) != 2 || !strings.HasPrefix(lines[0], a) || !strings.HasPrefix(lines[1], b) {
		t.Fatalf("code = %d, lines = %q", code, lines)
	}
}

func TestRunReadErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.txt")
	code, _, errOut := run(t, missing)
	if code != 2 || !strings.Contains(errOut, "missing.txt") {
		t.Fatalf("code = %d, stderr = %q", code, errOut)
	}
	dirty := writeFile(t, dir, "dirty.txt", "k: "+awsKey()+nl)
	if code, _, _ := run(t, missing, dirty); code != 1 {
		t.Fatalf("findings must win over read errors: code = %d", code)
	}
}

func TestRunCRLFMatchesLF(t *testing.T) {
	dir := t.TempDir()
	lines := "one" + nl + "k: " + awsKey() + nl
	lf := writeFile(t, dir, "lf.txt", lines)
	win := strings.ReplaceAll(lines, nl, crlf)
	cr := writeFile(t, dir, "crlf.txt", win)
	_, outLF, _ := run(t, lf)
	_, outCR, _ := run(t, cr)
	wantLF := strings.TrimPrefix(outLF, lf)
	wantCR := strings.TrimPrefix(outCR, cr)
	if wantLF != wantCR || wantLF == "" {
		t.Fatalf("LF = %q, CRLF = %q", wantLF, wantCR)
	}
}

func TestRunVersionAndHelp(t *testing.T) {
	code, out, _ := run(t, "--version")
	if code != 0 || !strings.Contains(out, "secrets-precommit dev") {
		t.Fatalf("version: code = %d, stdout = %q", code, out)
	}
	code, _, errOut := run(t, "-h")
	if code != 0 || !strings.Contains(errOut, "usage") {
		t.Fatalf("help: code = %d, stderr = %q", code, errOut)
	}
}
