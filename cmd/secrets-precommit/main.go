// Command secrets-precommit scans files for secrets and is meant to run as a
// pre-commit hook.
//
// Usage: secrets-precommit [--config FILE] [--format text|json] [--no-defaults] [--version] FILE...
//
// Exit codes: 0 when nothing was found, 1 when at least one potential secret
// was found, and 2 for usage errors, configuration errors or read errors when
// there are no findings. The output never contains a full secret.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	secretsprecommit "github.com/Trysac/u071-secrets-precommit"
)

// exitOK means nothing was found.
const exitOK = 0

// exitFindings means at least one potential secret was found.
const exitFindings = 1

// exitFailure means a usage, configuration or read error.
const exitFailure = 2

// version is the program version; it can be set with -ldflags.
var version = "dev"

func main() {
	os.Exit(Run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer, flags *flag.FlagSet) {
	fmt.Fprintln(w, "usage: secrets-precommit [--config FILE] [--format text|json] [--no-defaults] [--version] FILE...")
	flags.PrintDefaults()
}

func loadConfig(name string) (secretsprecommit.Config, error) {
	if name == "" {
		return secretsprecommit.Config{}, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return secretsprecommit.Config{}, err
	}
	defer func() { _ = f.Close() }()
	return secretsprecommit.LoadConfig(f)
}

func printFindings(w io.Writer, format string, findings []secretsprecommit.Finding) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(findings)
	}
	for _, f := range findings {
		if _, err := fmt.Fprintln(w, f); err != nil {
			return err
		}
	}
	return nil
}

// Run executes the command with the given arguments (without the program
// name) and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("secrets-precommit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { usage(stderr, flags) }
	configPath := flags.String("config", "", "path to a JSON config file with team rules and allowlists")
	format := flags.String("format", "text", "output format: text or json")
	noDefaults := flags.Bool("no-defaults", false, "disable the built-in rules")
	showVersion := flags.Bool("version", false, "print the version and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitFailure
	}
	if *showVersion {
		fmt.Fprintf(stdout, "secrets-precommit %s\n", version)
		return exitOK
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "secrets-precommit: unknown --format value (want text or json)")
		return exitFailure
	}
	files := flags.Args()
	if len(files) == 0 {
		fmt.Fprintln(stderr, "secrets-precommit: no files given")
		flags.Usage()
		return exitFailure
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "secrets-precommit: %v\n", err)
		return exitFailure
	}
	if *noDefaults {
		cfg.DisableDefaults = true
	}
	scanner, err := secretsprecommit.NewScanner(cfg, secretsprecommit.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "secrets-precommit: %v\n", err)
		return exitFailure
	}
	findings, scanErr := scanner.ScanFiles(files)
	if findings == nil {
		findings = []secretsprecommit.Finding{}
	}
	if err := printFindings(stdout, *format, findings); err != nil {
		fmt.Fprintf(stderr, "secrets-precommit: write output: %v\n", err)
		return exitFailure
	}
	if scanErr != nil {
		fmt.Fprintf(stderr, "secrets-precommit: %v\n", scanErr)
	}
	if len(findings) > 0 {
		fmt.Fprintf(stderr, "secrets-precommit: %d potential secret(s) found; add %s to a line to suppress it\n", len(findings), "secrets-precommit:allow")
		return exitFindings
	}
	if scanErr != nil {
		return exitFailure
	}
	return exitOK
}
