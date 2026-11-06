// Package secretsprecommit is a small, dependency-free Go library: Fast secret detector for pre-commit hooks in Go: ten RE2 rules, JSON team rules, entropy checks, allowlists and output that never prints a secret
//
// The public API is every exported identifier of this root package. Functions are pure: they do
// no I/O, keep no global mutable state and report invalid input through returned errors.
package secretsprecommit
