package exposed

import "github.com/JLugagne/egauth/tools/archtest/testdata/g08/root/internal/opts"

type sess struct {
	AMR        []string
	RememberMe bool
}

func Current() sess { return sess{} }

func Hidden() opts.Session { return opts.Session{} }

type Sessions map[string]struct{ Epoch uint64 }

func Anon() struct{ Factors []string } { return struct{ Factors []string }{} }

type quiet struct{ AMR []string }

func use() quiet { return quiet{} }
