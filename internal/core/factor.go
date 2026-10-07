package core

import (
	"slices"
	"strings"
)

// FactorRole classifies a factor for the multi-factor and freshness rules.
type FactorRole uint8

const (
	// RolePrimary factors establish who the user is.
	RolePrimary FactorRole = iota + 1
	// RoleSecond factors strengthen a bound Pending or session.
	RoleSecond
	// RoleQualifier factors qualify another factor of the same verification (user verification).
	RoleQualifier
)

// Factor is one authentication factor. Its code is the persisted, injective identifier; the
// codec stores codes, never ordinals. The zero Factor is invalid everywhere.
type Factor struct {
	code string
}

// The closed set of factors (DESIGN §4.1).
var (
	FactorPassword         = Factor{"pwd"}
	FactorEmailLink        = Factor{"email_link"}
	FactorEmailCode        = Factor{"email_code"}
	FactorSMSCode          = Factor{"sms_code"}
	FactorFederated        = Factor{"fed"}
	FactorExternal         = Factor{"ext"}
	FactorPasskey          = Factor{"pk"}
	FactorUserVerification = Factor{"uv"}
	FactorTOTP             = Factor{"totp"}
	FactorRecoveryCode     = Factor{"rc"}
	FactorPasskeyStepUp    = Factor{"pk_stepup"}
)

type factorInfo struct {
	role FactorRole
	amr  string
}

var factorTable = map[string]factorInfo{
	"pwd":        {RolePrimary, "pwd"},
	"email_link": {RolePrimary, "email"},
	"email_code": {RolePrimary, "otp"},
	"sms_code":   {RolePrimary, "sms"},
	"fed":        {RolePrimary, "fed"},
	"ext":        {RolePrimary, "ext"},
	"pk":         {RolePrimary, "hwk"},
	"uv":         {RoleQualifier, "user"},
	"totp":       {RoleSecond, "otp"},
	"rc":         {RoleSecond, "rc"},
	"pk_stepup":  {RoleSecond, "hwk"},
}

// FactorByCode returns the factor persisted as code, or ErrInvalidFactor for an unknown code.
func FactorByCode(code string) (Factor, error) {
	if _, ok := factorTable[code]; !ok {
		return Factor{}, ErrInvalidFactor
	}
	return Factor{code: code}, nil
}

// AllFactors returns every factor of the closed set, ordered by code.
func AllFactors() []Factor {
	out := make([]Factor, 0, len(factorTable))
	for code := range factorTable {
		out = append(out, Factor{code: code})
	}
	sortFactors(out)
	return out
}

// Code returns the persisted identifier, or "" for the zero Factor.
func (f Factor) Code() string {
	return f.code
}

// Valid reports whether f is a member of the closed set.
func (f Factor) Valid() bool {
	_, ok := factorTable[f.code]
	return ok
}

// Role returns the role of f, or 0 for an invalid factor.
func (f Factor) Role() FactorRole {
	return factorTable[f.code].role
}

// AMR returns the RFC 8176 value emitted for f. It is output-only interoperability data: no
// decision may be taken from it, because several factors share a value (C-09). A magic link
// maps to "email", never "otp" (I-18).
func (f Factor) AMR() string {
	return factorTable[f.code].amr
}

func sortFactors(fs []Factor) {
	slices.SortFunc(fs, func(a, b Factor) int { return strings.Compare(a.code, b.code) })
}

func unionFactors(a, b []Factor) []Factor {
	var out []Factor
	for _, f := range append(slices.Clone(a), b...) {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	sortFactors(out)
	return out
}

func hasRole(fs []Factor, r FactorRole) bool {
	return slices.ContainsFunc(fs, func(f Factor) bool { return f.Role() == r })
}

func multiFactor(fs []Factor) bool {
	if hasRole(fs, RolePrimary) && hasRole(fs, RoleSecond) {
		return true
	}
	return slices.Contains(fs, FactorPasskey) && slices.Contains(fs, FactorUserVerification)
}

func amrOf(fs []Factor) []string {
	var out []string
	for _, f := range fs {
		if v := f.AMR(); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if multiFactor(fs) {
		out = append(out, "mfa")
	}
	return out
}
