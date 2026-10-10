package journeytest_test

import (
	"testing"

	"github.com/JLugagne/egauth/internal/journeytest"
)

func TestProbes(t *testing.T) {
	for _, b := range []journeytest.Backend{journeytest.JWT, journeytest.Stateful} {
		t.Run(b.String(), func(t *testing.T) {
			w := journeytest.NewWorld(t, journeytest.Settings{Backend: b})
			rep := journeytest.Collect(worldProbes(w))
			if len(rep) == 0 {
				t.Fatal("the battery is empty")
			}
			rep.Check(t)
			t.Logf("%d probes", len(rep))
		})
	}
}

func TestProbesResourceServer(t *testing.T) {
	rw := journeytest.NewResourceWorld(t, journeytest.Settings{})
	rep := journeytest.Collect(resourceProbes(rw))
	if len(rep) == 0 {
		t.Fatal("the battery is empty")
	}
	rep.Check(t)
}
