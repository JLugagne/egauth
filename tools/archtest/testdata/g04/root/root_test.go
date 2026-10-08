package egauth

func helperMustPanic() {
	_ = "tests may say not configured"
	panic("ok in tests")
}

func MustInTest() int { return 0 }
