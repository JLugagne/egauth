package event

type Type string

const (
	Emitted         Type = "emitted"
	ViaHelper       Type = "via_helper"
	HelperUnused    Type = "helper_unused"
	Orphan          Type = "orphan"
	Reserved        Type = "reserved"
	ReservedEmitted Type = "reserved_emitted"
	NoSeverity      Type = "no_severity"
	TestOnly        Type = "test_only"
	Wrapped         Type = "wrapped"
	Filtered        Type = "filtered"
)

type Severity uint8

func (t Type) Severity() Severity {
	switch t {
	case Emitted, ViaHelper, HelperUnused, Orphan, Reserved, ReservedEmitted, TestOnly, Wrapped, Filtered:
		return 1
	}
	return 2
}
