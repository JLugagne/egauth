package egauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/deployment"
	"github.com/JLugagne/egauth/store/limiter"
)

const (
	dataKeyName       = "datakey"
	dataKeyLen        = 32
	heartbeatInterval = deployment.LivenessWindow / 3
	heartbeatTimeout  = 10 * time.Second
	probeValueBytes   = 16
)

func checkSchema[C any](ctx context.Context, cfg *Config[C], defaultedLimiter bool, v *problems) {
	stores := presentStores(&cfg.Storage, true)
	if !defaultedLimiter && present(cfg.RateLimit) {
		stores = append(stores, namedStore{"RateLimit", cfg.RateLimit})
	}
	for _, s := range stores {
		if err := s.base.Ping(ctx); err != nil {
			v.add(s.field, "schema or connectivity check failed: "+err.Error())
		}
	}
}

func openDataKey[C any](ctx context.Context, cfg *Config[C], v *problems) []byte {
	st := cfg.Storage.Deployment
	sealed, err := st.GetSealed(ctx, dataKeyName)
	switch {
	case err == nil:
		return unsealDataKey(ctx, cfg, sealed, v)
	case !errors.Is(err, store.ErrNotFound):
		v.add("Storage.Deployment", "reading the data key: "+err.Error())
		return nil
	}
	return createDataKey(ctx, cfg, v)
}

func createDataKey[C any](ctx context.Context, cfg *Config[C], v *problems) []byte {
	key := make([]byte, dataKeyLen)
	if _, err := rand.Read(key); err != nil {
		v.add("Storage.Deployment", "generating the data key: "+err.Error())
		return nil
	}
	ct, err := sealing.Seal(ctx, cfg.KEK, sealing.DataKey(), key)
	if err != nil {
		v.add("KEK", "cannot seal the data key: "+err.Error())
		return nil
	}
	stored, err := cfg.Storage.Deployment.PutSealedIfAbsent(ctx, dataKeyName, ct)
	switch {
	case err != nil:
		v.add("Storage.Deployment", "storing the data key: "+err.Error())
		return nil
	case stored:
		return key
	}
	sealed, err := cfg.Storage.Deployment.GetSealed(ctx, dataKeyName)
	if err != nil {
		v.add("Storage.Deployment", "reading the data key: "+err.Error())
		return nil
	}
	return unsealDataKey(ctx, cfg, sealed, v)
}

func unsealDataKey[C any](ctx context.Context, cfg *Config[C], sealed []byte, v *problems) []byte {
	opened, err := sealing.Open(ctx, cfg.KEK, sealing.DataKey(), sealed)
	if err != nil {
		v.add("KEK", "cannot open existing data (wrong or rotated-out key)")
		return nil
	}
	if len(opened.Plaintext) != dataKeyLen {
		v.add("Storage.Deployment", "the stored data key has "+strconv.Itoa(len(opened.Plaintext))+" bytes, not "+strconv.Itoa(dataKeyLen))
		return nil
	}
	if opened.Stale {
		resealDataKey(ctx, cfg, sealed, opened.Plaintext)
	}
	return opened.Plaintext
}

func resealDataKey[C any](ctx context.Context, cfg *Config[C], old, key []byte) {
	ct, err := sealing.Seal(ctx, cfg.KEK, sealing.DataKey(), key)
	if err != nil {
		return
	}
	_, _ = cfg.Storage.Deployment.ReplaceSealed(ctx, dataKeyName, deployment.Replacement{Old: old, New: ct})
}

func checkLegacySecrets[C any](ctx context.Context, cfg *Config[C], v *problems) {
	var total int64
	count := func(field string, f func(context.Context) (int64, error)) {
		n, err := f(ctx)
		if err != nil {
			v.add(field, "counting v0.16 secrets: "+err.Error())
			return
		}
		total += n
	}
	count("Storage.MFA", cfg.Storage.MFA.CountLegacySealed)
	if present(cfg.Storage.Federation) {
		count("Storage.Federation", cfg.Storage.Federation.CountLegacySealed)
	}
	if present(cfg.Storage.Keys) {
		count("Storage.Keys", cfg.Storage.Keys.CountLegacySealed)
	}
	if total > 0 {
		v.add("Storage", strconv.FormatInt(total, 10)+" v0.16 secrets not upgraded; run egauth.UpgradeSecretsV016")
	}
}

func checkEnrollments[C any](ctx context.Context, cfg *Config[C], v *problems) {
	m := &cfg.Modules
	if m.MFA == nil {
		enrolledWithoutModule(ctx, v, "Modules.MFA", "TOTP", cfg.Storage.MFA.AnyEnrolled, cfg.Storage.MFA.CountEnrolled)
	}
	if m.Passkey == nil {
		enrolledWithoutModule(ctx, v, "Modules.Passkey", "passkeys", cfg.Storage.Passkeys.AnyEnrolled, cfg.Storage.Passkeys.CountEnrolled)
	}
}

func enrolledWithoutModule(ctx context.Context, v *problems, field, what string, any func(context.Context) (bool, error), count func(context.Context) (int64, error)) {
	ok, err := any(ctx)
	if err != nil {
		v.add(field, "reading "+what+" enrollments: "+err.Error())
		return
	}
	if !ok {
		return
	}
	n, err := count(ctx)
	if err != nil || n < 1 {
		v.add(field, what+" enrolled but "+field+" is nil")
		return
	}
	v.add(field, what+" enrolled for "+strconv.FormatInt(n, 10)+" subjects but "+field+" is nil")
}

func probeLimiter(ctx context.Context, l httpx.Limiter) error {
	raw := make([]byte, probeValueBytes)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	key := limiter.Key{Class: limiter.SelfTest, Value: hex.EncodeToString(raw)}
	for range key.Class.Budget().Burst + 1 {
		d, err := l.Allow(ctx, key)
		if err != nil {
			return err
		}
		if !d.Allowed {
			return nil
		}
	}
	return errors.New("burst+1 requests were all allowed: the limiter enforces no budget")
}

type heartbeat struct {
	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func (o *owned) pulse(ctx context.Context, st deployment.Store) error {
	ctx, cancel := context.WithTimeout(ctx, heartbeatTimeout)
	defer cancel()
	live, err := st.Heartbeat(ctx, o.instance)
	if err != nil {
		return err
	}
	n := max(len(live), 1)
	o.instances.Store(int32(n))
	if o.scaleLimit {
		o.limiter.setInstances(n)
	}
	return nil
}

func (o *owned) startHeartbeat(st deployment.Store) {
	h := &heartbeat{stop: make(chan struct{}), done: make(chan struct{})}
	o.beat = h
	go func() {
		defer close(h.done)
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-h.stop:
				return
			case <-t.C:
				_ = o.pulse(context.Background(), st)
			}
		}
	}()
}

func (o *owned) stopHeartbeat() {
	if o.beat == nil {
		return
	}
	o.beat.once.Do(func() { close(o.beat.stop) })
	<-o.beat.done
}

func emit(ctx context.Context, sink event.Sink, t event.Type, reason string, attrs ...audit.Attr) {
	_ = audit.Emit(ctx, sink, t, audit.Scope{}, audit.Detail{Reason: reason}, nil, attrs...)
}

func finish[C any](ctx context.Context, cfg *Config[C], o *owned, v *problems) error {
	if err := o.pulse(ctx, cfg.Storage.Deployment); err != nil {
		v.add("Storage.Deployment", "recording the instance heartbeat: "+err.Error())
		return v.err()
	}
	if cfg.Insecure.NoRateLimit == nil {
		if err := probeLimiter(ctx, o.limiter); err != nil {
			v.add("RateLimit", "the startup probe failed: "+err.Error())
		}
	}
	for _, p := range o.pollers {
		if err := p.Poll(ctx); err != nil {
			v.add("Storage", "the first revocation poll failed: "+err.Error())
		}
	}
	return v.err()
}

func startWork[C any](cfg *Config[C], o *owned) {
	for _, p := range o.pollers {
		p.Start()
	}
	o.reaper.Start()
	o.startHeartbeat(cfg.Storage.Deployment)
	if o.scaleLimit {
		emit(context.Background(), o.events, event.LimiterPerInstance, "ephemeral_limiter_with_shared_stores", audit.A(event.KeyCount, int(o.instances.Load())))
	}
	for _, out := range optOuts(&cfg.Insecure) {
		if out.set {
			emit(context.Background(), o.events, event.InsecureConfiguration, out.ack.Reason(), audit.A(event.KeyPurpose, out.name))
		}
	}
}

func (o *owned) stop() error {
	o.stopHeartbeat()
	if o.reaper != nil {
		o.reaper.Stop()
	}
	for _, p := range o.pollers {
		p.Stop()
	}
	return o.closeAll()
}
