package shared

import "time"

type Record struct {
	Handle    string
	Owner     [16]byte
	ExpiresAt time.Time
}

type Plain struct{ Handle string }
