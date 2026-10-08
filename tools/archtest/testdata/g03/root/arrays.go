package egauth

import "github.com/JLugagne/egauth/tools/archtest/testdata/uuid"

type Ref uuid.UUID

type Digest [32]byte

type Point [2]float64

func SwapRef(a, b Ref) {}

func Digests(a, b Digest) {}

func RawDigests(a, b [32]byte) {}

func Points(a, b Point) {}

func MixedRefs(a Ref, b uuid.UUID) {}
