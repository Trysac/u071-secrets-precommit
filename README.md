# secrets-precommit

[![Go Reference](https://pkg.go.dev/badge/github.com/Trysac/u071-secrets-precommit.svg)](https://pkg.go.dev/github.com/Trysac/u071-secrets-precommit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Trysac/u071-secrets-precommit/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u071-secrets-precommit/actions/workflows/ci.yml)

Fast secret detector for pre-commit hooks in Go: ten RE2 rules, JSON team rules, entropy checks, allowlists and output that never prints a secret

## Problem

Full secret scanners are often too slow or too noisy to run on every commit, so developers disable them and secrets reach repositories. A pre-commit hook needs to scan only the staged files quickly, accept team-specific rules and never print the secret it finds. This utility is a small single binary, with a library behind it, that has stable exit codes and does exactly that.

## Install

```sh
go get github.com/Trysac/u071-secrets-precommit
go install github.com/Trysac/u071-secrets-precommit/cmd/secrets-precommit@latest
```

Requires Go 1.23 or newer. No dependencies outside the standard library.

## Usage

```go
package main

import (
	"fmt"
	"os"

	secretsprecommit "github.com/Trysac/u071-secrets-precommit"
)

func main() {
	s, _ := secretsprecommit.NewScanner(secretsprecommit.Config{}, secretsprecommit.Options{})
	findings, _ := s.ScanFiles(os.Args[1:])
	for _, f := range findings {
		fmt.Println(f.Path, f.Line, f.Column, f.RuleID, f.Redacted)
	}
}
```

From the command line, pass the staged files to the CLI. The pre-commit hook entry is:

```yaml
repos:
  - repo: local
    hooks:
      - id: secrets-precommit
        name: secrets-precommit
        entry: secrets-precommit
        language: system
```

## Public API

- `DefaultRules() []Rule`: the ten built-in rules. A `Rule` has `ID`, `Description`, `Pattern *regexp.Regexp`, `SecretGroup int` and `MinEntropy float64`.
- `type Config struct { Rules []RuleConfig; DisableDefaults bool; Allowlist struct { Paths, Regexes []string } }`, with camelCase JSON tags.
- `LoadConfig(r io.Reader) (Config, error)`: reads at most 1 MiB and rejects unknown JSON fields and trailing data.
- `NewScanner(cfg Config, opts Options) (*Scanner, error)`: `Options` has `OnEvent func(Event)`. An `Event` has `Kind` (skip or finding), `Path`, `RuleID` and `Reason`, and never carries a secret.
- `(*Scanner).ScanReader(path string, r io.Reader) ([]Finding, error)` and `(*Scanner).ScanFiles(paths []string) ([]Finding, error)`.
- `Finding` has `RuleID`, `Path`, `Line`, `Column` (1-based, in runes) and `Redacted`, with JSON tags `ruleId`, `path`, `line`, `column` and `redacted`.
- Errors: `ErrInvalidConfig` is returned for invalid configuration and is wrapped with the rule id where one applies. Read errors wrap the path.

Options and limits: team rule patterns are limited to 1000 bytes and 100 rules; the configuration is limited to 1 MiB. Files larger than 1 MiB, directories, symlinks and files with a NUL byte in the first 8 KiB are skipped. Allowlists match slash-separated paths and base names with `path.Match`, and value regexes match the captured secret. A line containing `secrets-precommit:allow` is ignored.

CLI: `secrets-precommit [--config FILE] [--format text|json] [--no-defaults] [--version] FILE...`. Exit code 0 means no findings, 1 means findings were reported, and 2 means no file arguments, an unknown flag, or a configuration or read error without findings.

## Why not gitleaks?

gitleaks is broader than this utility: it covers more rules and history scanning. This utility is narrower and aims to be fast on staged files with no runtime dependencies. detect-secrets needs Python, which this utility avoids.

## Security

The threat model, the defended cases and the known limits are described in [security](docs/SECURITY.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
