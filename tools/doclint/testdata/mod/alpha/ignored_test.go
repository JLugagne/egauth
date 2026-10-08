//go:build ignore

package alpha_test

func ExampleIgnored() {
	doesNotCompile(undefined)
}

func Anything() {
	doesNotCompile(undefined)
}
