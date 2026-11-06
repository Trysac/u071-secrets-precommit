package secretsprecommit

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
)

// CodeInvalidConfig is the [Error.Code] of every rejected configuration.
const CodeInvalidConfig = "invalid_config"

// CodeRead is the [Error.Code] of every failed read of a file or a config.
const CodeRead = "read_error"

// Error is the only error type returned by this package.
//
// Messages never contain secrets and never more than 200 characters of input.
type Error struct {
	// Code is a stable machine-readable identifier.
	Code string

	// Message is a human-readable description.
	Message string

	// Err is the underlying cause, if any.
	Err error
}

// Error implements the error interface.
func (e *Error) Error() string {
	return "secretsprecommit: " + e.Message
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	return e.Err
}

// Is reports whether target is an [Error] with the same Code, so that
// errors.Is(err, ErrInvalidConfig) matches every configuration error.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// ErrInvalidConfig matches every error caused by an invalid configuration.
var ErrInvalidConfig = &Error{Code: CodeInvalidConfig, Message: "invalid config"}

// ErrRead matches every error caused by a failed read; the message names the
// path and the cause is reachable through errors.Unwrap.
var ErrRead = &Error{Code: CodeRead, Message: "read error"}

// maxInputInMessage caps the amount of caller-supplied text in an error message.
const maxInputInMessage = 200

// truncate limits s to maxInputInMessage runes.
func truncate(s string) string {
	n := 0
	for i := range s {
		if n == maxInputInMessage {
			return s[:i] + "..."
		}
		n++
	}
	return s
}

// invalidf builds an invalid-configuration error.
func invalidf(format string, args ...any) error {
	return &Error{Code: CodeInvalidConfig, Message: fmt.Sprintf(format, args...)}
}

// readError wraps a read failure and names the path it concerns.
func readError(name string, err error) error {
	cause := err
	var pe *fs.PathError
	if errors.As(err, &pe) {
		cause = pe.Err
	}
	msg := "read " + strconv.Quote(truncate(name)) + ": " + truncate(cause.Error())
	return &Error{Code: CodeRead, Message: msg, Err: err}
}
