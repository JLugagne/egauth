package deployment_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/store/deployment"
	"github.com/google/uuid"
)

var (
	_ func(deployment.Store, context.Context, string, deployment.Replacement) (bool, error) = deployment.Store.ReplaceSealed
	_ func(deployment.Store, context.Context, string, []byte) (bool, error)                 = deployment.Store.PutSealedIfAbsent
	_ func(deployment.Store, context.Context, uuid.UUID) ([]deployment.Instance, error)     = deployment.Store.Heartbeat
	_ func(deployment.Store, context.Context) (int64, error)                                = deployment.Store.ReapExpired
)

func TestReplacementIsAPair(t *testing.T) {
	r := deployment.Replacement{Old: []byte{1}, New: []byte{2}}
	if r.Old[0] == r.New[0] {
		t.Fatal("old and new are distinct fields")
	}
}

func TestLivenessWindowIsALibraryConstant(t *testing.T) {
	if deployment.LivenessWindow < 30*time.Second || deployment.LivenessWindow > 5*time.Minute {
		t.Fatalf("LivenessWindow %v outside the range the per-instance limiter budget assumes", deployment.LivenessWindow)
	}
}
