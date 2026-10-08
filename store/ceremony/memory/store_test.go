package memory_test

import (
	"testing"

	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/ceremony/memory"
	"github.com/JLugagne/egauth/store/ceremony/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, ceremony.Restore)
	storetest.Run(t, func(*testing.T) ceremony.Store { return memory.New() })
}
