# Testing

## Running

```sh
go test -cover .          # tests with coverage summary
go run ./scripts/check    # every gate, as CI and the factory run it
```

## Policy

- Statement coverage of the library (every package except `scripts/`) must stay at or above 80 %; the gate fails below it.
- Tests live in package `secretsprecommit_test` and exercise the public API only. They assert observable effects: return values, returned errors (`errors.Is`) and their messages.
- Prefer table-driven tests with `t.Run` subtests. Usage is documented with runnable `Example` functions, which `go test` verifies through their `// Output:` comments.
- The race detector runs whenever cgo and a C compiler are available (always in Linux CI); the gate prints why when it has to run without it.
- Each bug fix starts with a failing test that reproduces it.
- Tests are deterministic: no network, no wall clock, no dependence on test order.

## Tests that exist

The tests are in the package's `_test.go` files, next to the code they test, and cover:

- `TestEverySampleDetectedAndNeverLeaked`: a runtime-built sample of every default rule is detected and the full secret never appears in output, errors or events.
- `TestTokenBoundaries`: token rules match at punctuation boundaries and not when touching another word character.
- `TestGenericAssignment`: entropy threshold, quoted values and the allow comment.
- `TestTeamRules`: JSON team rules and redaction of their matches.
- `TestLoadConfigRejects`: unknown fields, trailing data, invalid regexes and out-of-range values.
- `TestNewScannerLimits`: limits on team pattern length and rule count.
- `TestPathologicalInputsStayLinear`: long adversarial inputs.
- `TestSymlinkSkipped`, `TestBinaryAndTooLargeFilesSkipped`, `TestSizeAndSniffBoundaries`: file handling and skip events.
- `TestRunNeverPrintsSecrets`: CLI output and exit codes.

The ordering and column rules (CRLF files, sorting by path, line and column) are covered by the same suites.

## Layout

`<file>_test.go` sits next to the file it tests. Fixtures and golden files go in `testdata/`, but secret samples are never placed there; they are built at runtime.
