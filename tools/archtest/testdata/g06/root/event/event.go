package event

type Sink interface{ Emit(name string) }

const KeyAMR = "amr"
