package event

type Type string

const (
	AccountDisabled Type = "account_disabled"
	TypeNotWritten  Type = "x"
)

const SkipFlag = true
