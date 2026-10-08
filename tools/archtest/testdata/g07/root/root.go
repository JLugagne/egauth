package egauth

type InsecureOptOuts struct {
	InsecureCookies bool
	AllowHTTP       bool
	SkipCSRF        bool
}

type ResourceInsecure struct{ DisableAudience bool }

type Config struct {
	Insecure     InsecureOptOuts
	AllowHTTP    bool
	Name         string
	NoopLogger   bool
	Nothing      int
	ExportPrefix string
}

func (Config) DisableRateLimit() {}

func (Config) Validate() {}

func SkipChecks() {}

func UpgradeSecretsV016() {}

const LegacyMode = 1

var TLSDisabled bool

type Hooks interface {
	BypassAuth()
	Run()
}

func unexportedSkipX() {}
