# Linear-time RE2 rules with word-boundary wrapping and redacted-only output

Status: accepted (generated, pending human review)

## Context

A pre-commit secret detector must be fast, accept team rules without a ReDoS risk and never print the secret it finds. Go regexp is RE2 and has no lookaround, so a token touching other word characters cannot be excluded with lookbehind or lookahead.

## Decision

Use only the standard library. Every built-in token rule is wrapped in a non-word boundary group with the token as capture group 1, and scanning restarts at the end of each secret so tokens that are one character apart are all found. Matches are filtered by Shannon entropy and allowlists. Findings carry only a redacted prefix: the first min(4, runes/2) runes of the secret plus ****. Files are read fully but capped at 1 MiB, and symlinks, directories, special files and binary files are skipped. Errors use one typed Error with stable codes. The CLI lives in cmd/secrets-precommit and delegates to Run(args, stdout, stderr).

## Consequences

Matching is linear in input size for built-in and team rules. Tokens glued to other word characters are deliberately missed, which reduces false positives but misses secrets inside longer identifiers. Redaction hides the secret length. Team rules are not wrapped, so authors handle boundaries themselves. Secrets in git history, encoded or split secrets and provider verification are out of scope, and the rule set must be re-checked against upstream formats from time to time.
