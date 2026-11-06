// Package secretsprecommit is a fast secret detector built for pre-commit
// hooks.
//
// It scans the files it is given line by line with ten built-in RE2 rules,
// optional JSON team rules, Shannon entropy checks and allowlists. It never
// returns or prints a full secret: every [Finding] carries only the first
// runes of the secret followed by four asterisks.
//
// Go's regexp package implements RE2, so matching time is linear in the input
// size and neither the built-in rules nor team rules can cause catastrophic
// backtracking. Team patterns are limited to 1000 bytes and 100 rules, and a
// configuration is limited to 1 MiB.
//
// Rule data source: the token formats are adapted from the public default
// rules of gitleaks (config/gitleaks.toml in https://github.com/gitleaks/gitleaks).
// Check date: 2025-06-01.
//
// RE2 has no lookaround, so every token rule is wrapped in a word-boundary
// group that requires a non-word character (or the line edge) before and after
// the token. A token touching another letter, digit or underscore is not
// reported, while punctuation around it is fine.
//
// Files that are symlinks, directories, larger than 1 MiB or that contain a NUL
// byte in their first 8 KiB are skipped and reported through [Options.OnEvent].
// A line containing secrets-precommit:allow is never reported.
//
// Not covered: git history, secrets that are encoded or split across lines,
// provider-side verification and baselines.
package secretsprecommit
