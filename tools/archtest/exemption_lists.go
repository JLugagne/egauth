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

const maxG01Entries = 0

var g01Exemptions []Exemption

// G01Exemptions returns the exemptions that the workspace test filters CheckG01 findings with.
func G01Exemptions() ExemptionList {
	return ExemptionList{Guard: G01, MaxEntries: maxG01Entries, Entries: g01Exemptions}
}

const maxG02Entries = 0

var g02Exemptions []Exemption

// G02Exemptions returns the exemptions that the workspace test filters CheckG02 findings with.
func G02Exemptions() ExemptionList {
	return ExemptionList{Guard: G02, MaxEntries: maxG02Entries, Entries: g02Exemptions}
}

const maxG03Entries = 0

var g03Exemptions []Exemption

// G03Exemptions returns the exemptions that the workspace test filters CheckG03 findings with.
func G03Exemptions() ExemptionList {
	return ExemptionList{Guard: G03, MaxEntries: maxG03Entries, Entries: g03Exemptions}
}

const maxG04Entries = 0

var g04Exemptions []Exemption

// G04Exemptions returns the exemptions that the workspace test filters CheckG04 findings with.
func G04Exemptions() ExemptionList {
	return ExemptionList{Guard: G04, MaxEntries: maxG04Entries, Entries: g04Exemptions}
}

const maxG13Entries = 0

var g13Exemptions []Exemption

// G13Exemptions returns the exemptions that the workspace test filters CheckG13 findings with.
func G13Exemptions() ExemptionList {
	return ExemptionList{Guard: G13, MaxEntries: maxG13Entries, Entries: g13Exemptions}
}

const maxG14Entries = 3

var g14Exemptions = []Exemption{
	{Guard: G14, Symbol: "errors.As", RemovedBy: Permanent},
	{Guard: G14, Symbol: "net/http.Flusher", RemovedBy: Permanent},
	{Guard: G14, Symbol: "net/http.Hijacker", RemovedBy: Permanent},
}

// G14Exemptions returns the exemptions that the workspace test filters CheckG14 findings with.
func G14Exemptions() ExemptionList {
	return ExemptionList{Guard: G14, MaxEntries: maxG14Entries, Entries: g14Exemptions}
}

const maxG15Entries = 0

var g15Exemptions []Exemption

// G15Exemptions returns the exemptions that the workspace test filters CheckG15 findings with.
func G15Exemptions() ExemptionList {
	return ExemptionList{Guard: G15, MaxEntries: maxG15Entries, Entries: g15Exemptions}
}
