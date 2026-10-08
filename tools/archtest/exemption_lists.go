package archtest

func init() {
	RegisterList(G01Exemptions())
	RegisterList(G02Exemptions())
	RegisterList(G03Exemptions())
	RegisterList(G04Exemptions())
	RegisterList(G13Exemptions())
	RegisterList(G14Exemptions())
	RegisterList(G15Exemptions())
}

const maxG01Entries = LegacyPrefixCount

var g01Exemptions = LegacyExemptions(G01)

// G01Exemptions returns the exemptions that the workspace test filters CheckG01 findings with.
func G01Exemptions() ExemptionList {
	return ExemptionList{Guard: G01, MaxEntries: maxG01Entries, Entries: g01Exemptions}
}

const maxG02Entries = LegacyPrefixCount + 1

var g02Exemptions = append(LegacyExemptions(G02),
	Exemption{Guard: G02, Symbol: ModulePath + "/passwords/...", RemovedBy: WP7},
)

// G02Exemptions returns the exemptions that the workspace test filters CheckG02 findings with.
func G02Exemptions() ExemptionList {
	return ExemptionList{Guard: G02, MaxEntries: maxG02Entries, Entries: g02Exemptions}
}

const maxG03Entries = LegacyPrefixCount + 1

var g03Exemptions = append(LegacyExemptions(G03),
	Exemption{Guard: G03, Symbol: ModulePath + "/passwords/...", RemovedBy: WP7},
)

// G03Exemptions returns the exemptions that the workspace test filters CheckG03 findings with.
func G03Exemptions() ExemptionList {
	return ExemptionList{Guard: G03, MaxEntries: maxG03Entries, Entries: g03Exemptions}
}

const maxG04Entries = LegacyPrefixCount + 4

var g04Exemptions = append(LegacyExemptions(G04),
	Exemption{Guard: G04, Symbol: ModulePath + "/passwords/...", RemovedBy: WP7},
	Exemption{Guard: G04, Symbol: ModulePath + "/internal/redirect.ErrNoOrigins", RemovedBy: WP4},
	Exemption{Guard: G04, Symbol: ModulePath + "/internal/examplekey/...", RemovedBy: WP16},
	Exemption{Guard: G04, Symbol: ModulePath + "/event.Event.Err", RemovedBy: WP5},
)

// G04Exemptions returns the exemptions that the workspace test filters CheckG04 findings with.
func G04Exemptions() ExemptionList {
	return ExemptionList{Guard: G04, MaxEntries: maxG04Entries, Entries: g04Exemptions}
}

const maxG13Entries = LegacyPrefixCount + 2

var g13Exemptions = append(LegacyExemptions(G13),
	Exemption{Guard: G13, Symbol: ModulePath + ".ActorFromContext", RemovedBy: WP16},
	Exemption{Guard: G13, Symbol: ModulePath + ".ContextWithActor", RemovedBy: WP16},
)

// G13Exemptions returns the exemptions that the workspace test filters CheckG13 findings with.
func G13Exemptions() ExemptionList {
	return ExemptionList{Guard: G13, MaxEntries: maxG13Entries, Entries: g13Exemptions}
}

const maxG14Entries = LegacyPrefixCount + 4

var g14Exemptions = append(LegacyExemptions(G14),
	Exemption{Guard: G14, Symbol: "errors.As", RemovedBy: Permanent},
	Exemption{Guard: G14, Symbol: "net/http.Flusher", RemovedBy: Permanent},
	Exemption{Guard: G14, Symbol: "net/http.Hijacker", RemovedBy: Permanent},
	Exemption{Guard: G14, Symbol: ModulePath + "/examples/fullstack/...", RemovedBy: WP16},
)

// G14Exemptions returns the exemptions that the workspace test filters CheckG14 findings with.
func G14Exemptions() ExemptionList {
	return ExemptionList{Guard: G14, MaxEntries: maxG14Entries, Entries: g14Exemptions}
}

const maxG15Entries = LegacyPrefixCount

var g15Exemptions = LegacyExemptions(G15)

// G15Exemptions returns the exemptions that the workspace test filters CheckG15 findings with.
func G15Exemptions() ExemptionList {
	return ExemptionList{Guard: G15, MaxEntries: maxG15Entries, Entries: g15Exemptions}
}
