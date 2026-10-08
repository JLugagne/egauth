package egauth

import "github.com/JLugagne/egauth/tools/archtest/testdata/g03/root/principal"

func GenericAdj[T ~string](a, b T) {}

func GenericUnion[T ~string | ~int64](a, b T) {}

func GenericTenant[T principal.TenantID](a, b T) {}

type stringish interface{ ~string }

func GenericNamedConstraint[T stringish](a, b T) {}

func GenericResults[T ~string]() (a, b T) { return }

func GenericAny[T any](a, b T) {}

func GenericComparable[T comparable](a, b T) {}

func GenericFloat[T ~float64](a, b T) {}

type Fn[T any] func(a, b T)

func TakeFn(f Fn[string]) {}

type Two[T any] struct{}

func (Two[T]) Both() (a, b T) { return }

func NewTwo() Two[string] { return Two[string]{} }

type Keyed[T any] interface{ Find(a, b T) }

func NewKeyed() Keyed[int64] { return nil }

type FloatFn[T any] func(a, b T)

func TakeFloatFn(f FloatFn[float64]) {}
