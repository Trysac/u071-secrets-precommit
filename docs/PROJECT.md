# Project record

## Objective

Provide a fast, stdlib-only secret detector for pre-commit hooks. It scans only the files it is given, accepts team-specific JSON rules, applies entropy checks and allowlists, and never prints a full secret.

## Scope

- In scope: the public API documented in [README.md](../README.md), the ten built-in rules, JSON team rules, entropy checks on captured values, path and regex allowlists, redacted text and JSON output, and the CLI `secrets-precommit` with exit codes 0, 1 and 2.
- Out of scope: scanning the git index or git history, verification of secrets with providers, baselines of known findings, and any dependency outside the standard library or any I/O beyond reading the given files and configuration, unless accepted in an ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 244009 / 132367 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.7218 |

## Factory run u071 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2507 | 120468 | 0 | 4285 | 0.6053 |
| fix-1 | claude-sonnet-5-5 | no | 8 | 840 | 6965 | 55371 | 0.0314 |
| fix-2 | claude-sonnet-5-5 | no | 10 | 807 | 4678 | 73294 | 0.0271 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 942 | 4458 | 42757 | 0.0249 |
| fix-4 | claude-sonnet-5-5 | no | 8 | 1036 | 4845 | 58007 | 0.0283 |
| docs | claude-haiku-5-5 | no | 7756 | 8274 | 0 | 0 | 0.0049 |

Total: $0.7218. Prices: Anthropic list prices.
