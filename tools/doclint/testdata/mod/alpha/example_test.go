package alpha_test

import (
	"fmt"

	"example.com/fixture/alpha"
)

func ExampleNew() {
	s := alpha.New()
	s.Start()
	fmt.Println("ok")
	// Output: ok
}

func ExampleWithArg(n int) {
	fmt.Println(n)
}

func Anything() {
	fmt.Println("not an example")
}
