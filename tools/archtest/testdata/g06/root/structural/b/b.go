package b

import (
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/kek"
	"github.com/JLugagne/egauth/tools/archtest/testdata/g06/root/structural/a"
)

func Run(k kek.KEK) { a.Do(k) }

func RunGeneric(k kek.KEK) { a.DoGeneric(k) }

func RunSlice(k kek.KEK) []a.Sealer { return append([]a.Sealer{}, k) }

func Back(k kek.KEK) a.Sealer { return k }

func Clean(k kek.KEK) kek.KEK { return k }
