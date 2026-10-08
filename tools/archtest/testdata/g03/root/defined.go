package egauth

type Ident string

type Level int

type Blob []byte

type Flag bool

func Swap(tenant, user Ident) {}

func Range(lo, hi Level) {}

func Blobs(a, b Blob) {}

func Flags(a, b Flag) {}

func Mixed(a Ident, b string) {}
