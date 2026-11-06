# Architecture

## Purpose

`github.com/Trysac/u071-secrets-precommit` is a small, dependency-free Go module. Its root package `secretsprecommit` detects secrets in text using ten built-in RE2 rules and optional JSON team rules, applies entropy checks and allowlists, and reports findings with redacted secrets only. The CLI in `cmd/secrets-precommit` is a thin wrapper.

## Shape

```text
caller code --> package secretsprecommit (repository root)
                    |
                    +-- scanner, rules, config, findings (no global mutable state)
                    |
cmd/secrets-precommit/main.go
                    +-- Run(args []string, stdout, stderr io.Writer) int (stdlib only)
```

- **Public API**: every exported identifier of the root package, including `DefaultRules`, `LoadConfig`, `NewScanner`, `Scanner`, `Finding`, `Event` and `ErrInvalidConfig`. Unexported identifiers and internal packages may change without a major version.
- **Errors**: invalid input returns an error; exported sentinel errors such as `ErrInvalidConfig` let callers branch with `errors.Is`. The library does not panic on input, print or exit.
- **Side effects**: the library reads only the readers and files it is given. Files are checked with `os.Lstat` first; symlinks, directories, oversized and binary files are skipped and reported through `OnEvent`. Printing and exit codes live only in the CLI.
- **Regular expressions**: Go `regexp` is RE2 and runs in linear time. Token rules are wrapped so that a match must not touch another word character, because RE2 has no lookaround.

## Quality contract

`scripts/check` is the single definition of the gates; `fabrica.json` tells the factory and CI how to run it. See [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
