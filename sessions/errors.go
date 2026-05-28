package sessions

import "errors"

var (
	// ErrSessionNotFound is returned when a session cannot be found.
	ErrSessionNotFound = errors.New("session not found")
)
