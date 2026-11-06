package secretsprecommit

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// MaxFileSize is the largest file, in bytes, that is scanned. Larger inputs
// are skipped with the reason "too_large".
const MaxFileSize = 1 << 20

// sniffSize is the number of leading bytes inspected for NUL bytes.
const sniffSize = 8 << 10

// allowMarker disables reporting for the line that contains it.
const allowMarker = "secrets-precommit:allow"

// EventKind tells what an [Event] reports.
type EventKind string

// EventSkip reports a file that was not scanned.
const EventSkip EventKind = "skip"

// EventFinding reports a finding; it carries the rule id but never the secret.
const EventFinding EventKind = "finding"

// Event is a notification delivered to [Options.OnEvent]. It never carries a
// secret.
type Event struct {
	// Kind is EventSkip or EventFinding.
	Kind EventKind

	// Path is the path of the file concerned.
	Path string

	// RuleID is set for findings.
	RuleID string

	// Reason is set for skips: binary, too_large, symlink, directory,
	// not_regular, allowlisted or changed.
	Reason string
}

// Options configures a [Scanner].
type Options struct {
	// OnEvent, if set, is called synchronously for every skipped file and
	// every finding.
	OnEvent func(Event)
}

// Scanner scans text for secrets. It is immutable after creation and safe for
// concurrent use as long as OnEvent is.
type Scanner struct {
	cfg     compiled
	onEvent func(Event)
}

// NewScanner validates cfg and returns a scanner. Errors match
// [ErrInvalidConfig].
func NewScanner(cfg Config, opts Options) (*Scanner, error) {
	c, err := compileConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Scanner{cfg: c, onEvent: opts.OnEvent}, nil
}

func (s *Scanner) emit(e Event) {
	if s.onEvent != nil {
		s.onEvent(e)
	}
}

func (s *Scanner) skip(name, reason string) {
	s.emit(Event{Kind: EventSkip, Path: name, Reason: reason})
}

// pathAllowed reports whether name matches an allowlist glob, either as a
// slash-separated path or as a base name.
func (s *Scanner) pathAllowed(name string) bool {
	if len(s.cfg.allowPaths) == 0 {
		return false
	}
	slash := filepath.ToSlash(name)
	base := path.Base(slash)
	for _, glob := range s.cfg.allowPaths {
		if ok, _ := path.Match(glob, slash); ok {
			return true
		}
		if ok, _ := path.Match(glob, base); ok {
			return true
		}
	}
	return false
}

func (s *Scanner) accept(rule *scanRule, secret string) bool {
	if rule.MinEntropy > 0 && shannon(secret) < rule.MinEntropy {
		return false
	}
	for _, re := range s.cfg.allowRegexes {
		if re.MatchString(secret) {
			return false
		}
	}
	return true
}

// scanLine appends the findings of one line to out. After a match the search
// restarts at the end of the secret, so tokens separated by a single
// punctuation character are all found.
func (s *Scanner) scanLine(out []Finding, name string, lineNo int, line string) []Finding {
	if strings.Contains(line, allowMarker) {
		return out
	}
	for i := range s.cfg.rules {
		rule := &s.cfg.rules[i]
		idx := 2 * rule.SecretGroup
		for pos := 0; pos <= len(line); {
			loc := rule.Pattern.FindStringSubmatchIndex(line[pos:])
			if loc == nil {
				break
			}
			step := loc[1]
			gs, ge := -1, -1
			if idx+1 < len(loc) {
				gs, ge = loc[idx], loc[idx+1]
			}
			if gs >= 0 && ge > gs {
				if rule.anchored && pos > 0 && gs == 0 {
					pos++
					continue
				}
				secret := line[pos+gs : pos+ge]
				if s.accept(rule, secret) {
					col := utf8.RuneCountInString(line[:pos+gs]) + 1
					out = append(out, Finding{RuleID: rule.ID, Path: name, Line: lineNo, Column: col, Redacted: redact(secret)})
				}
				step = ge
			}
			pos += max(step, 1)
		}
	}
	return out
}

func sortFindings(list []Finding) {
	slices.SortFunc(list, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line), cmp.Compare(a.Column, b.Column), cmp.Compare(a.RuleID, b.RuleID))
	})
}

// ScanReader scans r as the file called name. At most [MaxFileSize] bytes are
// read; a larger input, an input with a NUL byte in its first 8 KiB or a name
// matching the path allowlist is skipped and reported through OnEvent. A
// trailing CR is stripped from every line, so CRLF and LF files yield the same
// columns. Findings are sorted by path, line and column. Read errors match
// [ErrRead].
func (s *Scanner) ScanReader(name string, r io.Reader) ([]Finding, error) {
	if s.pathAllowed(name) {
		s.skip(name, "allowlisted")
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil {
		return nil, readError(name, err)
	}
	if len(data) > MaxFileSize {
		s.skip(name, "too_large")
		return nil, nil
	}
	head := data
	if len(head) > sniffSize {
		head = head[:sniffSize]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		s.skip(name, "binary")
		return nil, nil
	}
	var findings []Finding
	text := string(data)
	for lineNo := 1; ; lineNo++ {
		end := strings.IndexByte(text, '\n')
		line := text
		if end >= 0 {
			line = text[:end]
		}
		findings = s.scanLine(findings, name, lineNo, strings.TrimSuffix(line, "\r"))
		if end < 0 {
			break
		}
		text = text[end+1:]
	}
	sortFindings(findings)
	for _, f := range findings {
		s.emit(Event{Kind: EventFinding, Path: name, RuleID: f.RuleID})
	}
	return findings, nil
}

// ScanFiles scans every path. Symlinks, directories, special files and files
// larger than [MaxFileSize] are skipped without being opened; each skip is
// reported through OnEvent. A file that cannot be read does not stop the scan:
// its error, which matches [ErrRead], is joined into the returned error while
// the findings of the other files are still returned, sorted by path, line and
// column.
func (s *Scanner) ScanFiles(paths []string) ([]Finding, error) {
	var all []Finding
	var errs []error
	for _, p := range paths {
		found, err := s.scanFile(p)
		all = append(all, found...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	sortFindings(all)
	return all, errors.Join(errs...)
}

func (s *Scanner) scanFile(name string) ([]Finding, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, readError(name, err)
	}
	mode := info.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		s.skip(name, "symlink")
		return nil, nil
	case info.IsDir():
		s.skip(name, "directory")
		return nil, nil
	case !mode.IsRegular():
		s.skip(name, "not_regular")
		return nil, nil
	case info.Size() > MaxFileSize:
		s.skip(name, "too_large")
		return nil, nil
	case s.pathAllowed(name):
		s.skip(name, "allowlisted")
		return nil, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, readError(name, err)
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, readError(name, err)
	}
	if !os.SameFile(info, opened) {
		s.skip(name, "changed")
		return nil, nil
	}
	return s.ScanReader(name, f)
}
