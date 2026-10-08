package reg

import "github.com/JLugagne/egauth/tools/archtest/testdata/g16/root/internal/migrate"

func moduleStub() migrate.Module { return migrate.Module{Name: "stub"} }

func moduleNilStub() migrate.Module { return migrate.Module{Name: "nil", FS: nil} }
