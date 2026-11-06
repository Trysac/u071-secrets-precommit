# Security

## Threat model

`secrets-precommit` runs on a developer machine, on the files a hook passes to it. The files are untrusted text: they can be huge, binary, symlinks or crafted to make a scanner slow or to make it print a secret. The configuration file is trusted less than code but more than the scanned files, and it is validated strictly.

## Defended

Each item has a test that tries to break it.

- **Listed token formats.** The nine token rules detect their formats and skip a token that touches another word character. Tests: `TestEverySampleDetectedAndNeverLeaked`, `TestTokenBoundaries`.
- **High-entropy assignments.** `generic-assignment` requires a quoted value of at least 12 characters with at least 3.5 bits of Shannon entropy per byte. Test: `TestGenericAssignment`.
- **Leakage in output.** Findings, JSON, text lines, errors and events carry at most the first four runes of a secret plus `****`, never the length. A secret shorter than 8 runes shows at most half of its runes, so only team rules can produce a short redaction. Control characters in `Redacted` are replaced with `?`, and paths with control characters are quoted in `Finding.String`. Tests: `TestEverySampleDetectedAndNeverLeaked`, `TestTeamRules`, `TestRunNeverPrintsSecrets`.
- **ReDoS.** Go regexp is RE2 and runs in linear time. Team patterns are limited to 1000 bytes and 100 rules, and the configuration to 1 MiB. Tests: `TestPathologicalInputsStayLinear`, `TestNewScannerLimits`.
- **Symlink reads.** Paths are checked with `os.Lstat` first and symlinks are skipped. Test: `TestSymlinkSkipped`.
- **Huge or binary files.** Files over 1 MiB and files with a NUL byte in the first 8 KiB are skipped, and at most 1 MiB is ever read. Tests: `TestBinaryAndTooLargeFilesSkipped`, `TestSizeAndSniffBoundaries`.
- **Bad configuration.** Unknown fields, trailing data, invalid regexes and out-of-range values are rejected with an error that matches `ErrInvalidConfig`. Test: `TestLoadConfigRejects`.

## Not defended

- Secrets already present in git history; only the given files are scanned.
- Encoded secrets (base64, hex, URL encoding) and secrets split across lines or string concatenations.
- Provider-side verification: a match may be a false positive, and a valid secret in an unknown format is missed.
- Anyone who can edit the allowlist or add `secrets-precommit:allow` to a line can suppress findings.

Test fixtures contain no real or fake secrets in `testdata/`: tests build sample secrets at runtime in code, so the repository's own secret scanning does not flag them.

## Reporting a vulnerability

See `SECURITY.md` in the repository root.
