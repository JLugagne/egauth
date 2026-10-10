package journeytest

import (
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
)

// Primary is the first-factor dimension of the G23 journey matrix.
type Primary string

// Primaries of the matrix, in DESIGN section 9.4 order.
const (
	PrimaryRegister             Primary = "register"
	PrimaryPassword             Primary = "password"
	PrimaryMagicLink            Primary = "magic_link"
	PrimaryEmailCode            Primary = "email_code"
	PrimarySMSCode              Primary = "sms_code"
	PrimaryPasskeyUsernameFirst Primary = "passkey_username_first"
	PrimaryPasskeyDiscoverable  Primary = "passkey_discoverable"
	PrimaryOAuthOIDC            Primary = "oauth_oidc"
	PrimaryOAuthPlain           Primary = "oauth_plain"
	PrimaryExternal             Primary = "external"
)

// Primaries returns every primary of the matrix in a fixed order.
func Primaries() []Primary {
	return []Primary{
		PrimaryRegister, PrimaryPassword, PrimaryMagicLink, PrimaryEmailCode, PrimarySMSCode,
		PrimaryPasskeyUsernameFirst, PrimaryPasskeyDiscoverable, PrimaryOAuthOIDC, PrimaryOAuthPlain, PrimaryExternal,
	}
}

// MFA is the second-factor dimension of the G23 journey matrix.
type MFA string

// Second factors of the matrix; MFANone is an account with no enrolled second factor.
const (
	MFANone          MFA = "none"
	MFATOTP          MFA = "totp"
	MFARecoveryCode  MFA = "recovery_code"
	MFAPasskeyStepUp MFA = "passkey_stepup"
)

// MFAs returns every second-factor variant of the matrix in a fixed order.
func MFAs() []MFA {
	return []MFA{MFANone, MFATOTP, MFARecoveryCode, MFAPasskeyStepUp}
}

// Carrier is the transport dimension: the credentials travel in cookies or as Bearer tokens.
type Carrier uint8

const (
	Cookies Carrier = iota + 1
	Bearer
)

func (c Carrier) String() string {
	if c == Bearer {
		return "bearer"
	}
	return "cookies"
}

func tenancyName(t Tenancy) string {
	if t == Single {
		return "single"
	}
	return "subdomain"
}

// Cell is one point of the G23 journey matrix.
type Cell struct {
	Primary Primary
	MFA     MFA
	Backend Backend
	Carrier Carrier
	Tenancy Tenancy
}

// String renders c as primary+mfa/backend/carrier/tenancy, the line format of the pinned short matrix.
func (c Cell) String() string {
	return string(c.Primary) + "+" + string(c.MFA) + "/" + c.Backend.String() + "/" + c.Carrier.String() + "/" + tenancyName(c.Tenancy)
}

// ParseCell is the inverse of Cell.String.
func ParseCell(s string) (Cell, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 4 {
		return Cell{}, errors.New("journeytest: malformed cell " + s)
	}
	head, mfa, ok := strings.Cut(parts[0], "+")
	if !ok {
		return Cell{}, errors.New("journeytest: malformed cell " + s)
	}
	c := Cell{Primary: Primary(head), MFA: MFA(mfa)}
	switch parts[1] {
	case "jwt":
		c.Backend = JWT
	case "stateful":
		c.Backend = Stateful
	default:
		return Cell{}, errors.New("journeytest: unknown backend in cell " + s)
	}
	switch parts[2] {
	case "cookies":
		c.Carrier = Cookies
	case "bearer":
		c.Carrier = Bearer
	default:
		return Cell{}, errors.New("journeytest: unknown carrier in cell " + s)
	}
	switch parts[3] {
	case "single":
		c.Tenancy = Single
	case "subdomain":
		c.Tenancy = Subdomain
	default:
		return Cell{}, errors.New("journeytest: unknown tenancy in cell " + s)
	}
	if !slices.Contains(Primaries(), c.Primary) || !slices.Contains(MFAs(), c.MFA) {
		return Cell{}, errors.New("journeytest: unknown primary or mfa in cell " + s)
	}
	return c, nil
}

func backends() []Backend  { return []Backend{JWT, Stateful} }
func carriers() []Carrier  { return []Carrier{Cookies, Bearer} }
func tenancies() []Tenancy { return []Tenancy{Single, Subdomain} }

// AllCells returns the whole cross product of the five dimensions, invalid cells included, in a fixed order.
func AllCells() []Cell {
	var out []Cell
	for _, p := range Primaries() {
		for _, m := range MFAs() {
			for _, b := range backends() {
				for _, c := range carriers() {
					for _, t := range tenancies() {
						out = append(out, Cell{Primary: p, MFA: m, Backend: b, Carrier: c, Tenancy: t})
					}
				}
			}
		}
	}
	return out
}

// FullMatrix returns every valid cell: the cross product minus the cells a typed exemption names.
func FullMatrix() []Cell {
	var out []Cell
	for _, c := range AllCells() {
		if _, skipped := Exempted(c); !skipped {
			out = append(out, c)
		}
	}
	return out
}

// PrimaryByMFA returns every valid primary x MFA cell on JWT, Cookies and Single.
func PrimaryByMFA() []Cell {
	var out []Cell
	for _, p := range Primaries() {
		for _, m := range MFAs() {
			c := Cell{Primary: p, MFA: m, Backend: JWT, Carrier: Cookies, Tenancy: Single}
			if _, skipped := Exempted(c); !skipped {
				out = append(out, c)
			}
		}
	}
	return out
}

// PairwiseSeed is the seed of the pairwise covering array pinned in the short matrix.
const PairwiseSeed = 1

// Pairwise returns the IPOG pairwise covering array over the five dimensions, restricted to valid
// cells and tie-broken by a PCG generator seeded with seed. The same seed gives the same array.
func Pairwise(seed uint64) []Cell {
	domains := []int{len(Primaries()), len(MFAs()), len(backends()), len(carriers()), len(tenancies())}
	valid := func(p, m int) bool {
		_, skipped := Exempted(Cell{Primary: Primaries()[p], MFA: MFAs()[m]})
		return !skipped
	}
	rows := ipog(domains, valid, rand.New(rand.NewPCG(seed, seed)))
	out := make([]Cell, len(rows))
	for i, r := range rows {
		out[i] = Cell{Primary: Primaries()[r[0]], MFA: MFAs()[r[1]], Backend: backends()[r[2]], Carrier: carriers()[r[3]], Tenancy: tenancies()[r[4]]}
	}
	return out
}

// ShortMatrix returns the matrix of make check: every primary x MFA cell on JWT, Cookies and
// Single, united with the seed-1 pairwise covering array, without duplicates, in FullMatrix order.
func ShortMatrix() []Cell {
	in := map[Cell]bool{}
	for _, c := range PrimaryByMFA() {
		in[c] = true
	}
	for _, c := range Pairwise(PairwiseSeed) {
		in[c] = true
	}
	var out []Cell
	for _, c := range FullMatrix() {
		if in[c] {
			out = append(out, c)
		}
	}
	return out
}

// Golden renders cells one per line, the format of testdata/short-matrix.golden.
func Golden(cells []Cell) string {
	var b strings.Builder
	for _, c := range cells {
		b.WriteString(c.String())
		b.WriteByte('\n')
	}
	return b.String()
}

type pair struct{ i, vi, k, vk int }

func ipog(domains []int, valid func(p, m int) bool, rng *rand.Rand) [][]int {
	n := len(domains)
	blank := func() []int {
		r := make([]int, n)
		for x := range r {
			r[x] = -1
		}
		return r
	}
	var rows [][]int
	for p := range domains[0] {
		for m := range domains[1] {
			if valid(p, m) {
				r := blank()
				r[0], r[1] = p, m
				rows = append(rows, r)
			}
		}
	}
	for k := 2; k < n; k++ {
		uncovered := map[pair]bool{}
		for i := range k {
			for vi := range domains[i] {
				for vk := range domains[k] {
					uncovered[pair{i, vi, k, vk}] = true
				}
			}
		}
		cover := func(r []int) {
			for i := range k {
				delete(uncovered, pair{i, r[i], k, r[k]})
			}
		}
		for _, r := range rows {
			best, ties := -1, []int(nil)
			for v := range domains[k] {
				gain := 0
				for i := range k {
					if uncovered[pair{i, r[i], k, v}] {
						gain++
					}
				}
				switch {
				case gain > best:
					best, ties = gain, []int{v}
				case gain == best:
					ties = append(ties, v)
				}
			}
			r[k] = ties[rng.IntN(len(ties))]
			cover(r)
		}
		for _, pr := range orderedPairs(uncovered, domains, k) {
			if !uncovered[pr] {
				continue
			}
			row := blank()
			for {
				for x := range k {
					row[x] = rng.IntN(domains[x])
				}
				row[pr.i] = pr.vi
				if valid(row[0], row[1]) {
					break
				}
			}
			row[k] = pr.vk
			rows = append(rows, row)
			cover(row)
		}
	}
	return rows
}

func orderedPairs(set map[pair]bool, domains []int, k int) []pair {
	var out []pair
	for i := range k {
		for vi := range domains[i] {
			for vk := range domains[k] {
				if p := (pair{i, vi, k, vk}); set[p] {
					out = append(out, p)
				}
			}
		}
	}
	return out
}
