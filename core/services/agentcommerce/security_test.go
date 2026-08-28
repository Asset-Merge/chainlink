package agentcommerce

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type failOnceAudit struct {
	log      AuditLog
	failures atomic.Int32
}

func (a *failOnceAudit) Store(ctx context.Context, key, k, r string, p any) error {
	if a.failures.CompareAndSwap(1, 0) {
		return errors.New("transient audit failure")
	}
	return a.log.Store(ctx, key, k, r, p)
}

type failOnceEscrow struct {
	inner    *InMemoryEscrow
	failures atomic.Int32
}
type expiryRefundEscrow struct{ inner *InMemoryEscrow }

func (e *expiryRefundEscrow) Lock(c context.Context, i SignedIntent) (EscrowReceipt, error) {
	return e.inner.Lock(c, i)
}
func (e *expiryRefundEscrow) Release(context.Context, string) (SettlementReceipt, error) {
	return SettlementReceipt{}, ErrEscrowExpired
}
func (e *expiryRefundEscrow) Refund(c context.Context, _ string) (SettlementReceipt, error) {
	<-c.Done()
	return SettlementReceipt{}, c.Err()
}

func (e *failOnceEscrow) Lock(c context.Context, i SignedIntent) (EscrowReceipt, error) {
	if e.failures.CompareAndSwap(1, 0) {
		return EscrowReceipt{}, errors.New("transient lock failure")
	}
	return e.inner.Lock(c, i)
}
func (e *failOnceEscrow) Release(c context.Context, id string) (SettlementReceipt, error) {
	return e.inner.Release(c, id)
}
func (e *failOnceEscrow) Refund(c context.Context, id string) (SettlementReceipt, error) {
	return e.inner.Refund(c, id)
}

func transactionHarness(t *testing.T, a AuditStore, e Escrow) (*Orchestrator, ServiceQuery, ServiceRequest, Wallet) {
	t.Helper()
	keys := &sync.Map{}
	buyer, _ := NewEd25519Wallet(keys)
	seller, _ := NewEd25519Wallet(keys)
	d := NewInMemoryDirectory()
	if err := d.Register(AgentProfile{ID: seller.Address(), Capabilities: []string{"proof"}, Pricing: map[string]Amount{"proof": {1, "LINK", "escrow"}}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	o, err := NewOrchestrator(OrchestratorConfig{Directory: d, Escrow: e, Reputation: NewInMemoryReputation(), Audit: a, Wallet: buyer, Replay: NewInMemoryReplayStore(), Finalizations: NewInMemoryFinalizationStore(), Now: func() time.Time { return now }, ExecuteAs: func(context.Context, SignedIntent) ([]byte, map[string]string, error) {
		return []byte("output"), nil, nil
	}, VerifyWith: func(context.Context, SignedIntent, Proof) (VerificationResult, error) {
		return VerificationResult{Verified: true, Method: "oracle", SatisfiedConditions: []string{"oracle"}, Time: now}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	q := ServiceQuery{Capability: "proof", MaxPrice: Amount{2, "LINK", "escrow"}, SettlementRail: "escrow"}
	r := ServiceRequest{Service: "proof", SettlementChain: "chain", Nonce: "fixed-nonce-000000000000", EscrowTerms: EscrowTerms{ReleaseConditions: []string{"oracle"}, Expiration: time.Hour}}
	return o, q, r, seller
}

func validTerms() IntentTerms {
	return IntentTerms{ServiceRequest: ServiceRequest{Service: "proof", SettlementChain: "chain-1", Nonce: "0123456789abcdef0123456789abcdef", EscrowTerms: EscrowTerms{ReleaseConditions: []string{"oracle"}, Expiration: time.Hour}}, Price: Amount{Value: 1, Currency: "LINK", Rail: "escrow"}, Buyer: "buyer", Seller: "seller", Timestamp: time.Now().UTC()}
}

func TestEscrowTerminalStateAndReplayInvariants(t *testing.T) {
	terms := validTerms()
	h, err := IntentHash(terms)
	if err != nil {
		t.Fatal(err)
	}
	e := NewInMemoryEscrow()
	r, err := e.Lock(context.Background(), SignedIntent{Terms: terms, Hash: h})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Lock(context.Background(), SignedIntent{Terms: terms, Hash: h}); !errors.Is(err, ErrIntentReplay) {
		t.Fatalf("lock replay: %v", err)
	}
	first, err := e.Refund(context.Background(), r.EscrowID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Refund(context.Background(), r.EscrowID)
	if err != nil || first != second {
		t.Fatalf("refund is not idempotent: %#v %#v %v", first, second, err)
	}
	if _, err = e.Release(context.Background(), r.EscrowID); !errors.Is(err, ErrEscrowAlreadySettled) {
		t.Fatalf("release after refund: %v", err)
	}
}

func TestExpiredEscrowNeverReleases(t *testing.T) {
	now := time.Now().UTC()
	terms := validTerms()
	terms.Timestamp = now
	terms.EscrowTerms.Expiration = time.Second
	h, _ := IntentHash(terms)
	clock := now
	e := NewInMemoryEscrowWithClock(func() time.Time { return clock })
	r, err := e.Lock(context.Background(), SignedIntent{Terms: terms, Hash: h})
	if err != nil {
		t.Fatal(err)
	}
	clock = now.Add(2 * time.Second)
	if _, err = e.Release(context.Background(), r.EscrowID); !errors.Is(err, ErrEscrowExpired) {
		t.Fatalf("release: %v", err)
	}
	if got, err := e.Refund(context.Background(), r.EscrowID); err != nil || got.Status != "refunded" {
		t.Fatalf("refund: %#v %v", got, err)
	}
}

func TestConcurrentEscrowHasExactlyOneTerminalOutcome(t *testing.T) {
	terms := validTerms()
	h, _ := IntentHash(terms)
	e := NewInMemoryEscrow()
	r, _ := e.Lock(context.Background(), SignedIntent{Terms: terms, Hash: h})
	var wg sync.WaitGroup
	outcomes := make(chan string, 2)
	for _, release := range []bool{true, false} {
		wg.Add(1)
		go func(release bool) {
			defer wg.Done()
			var x SettlementReceipt
			var err error
			if release {
				x, err = e.Release(context.Background(), r.EscrowID)
			} else {
				x, err = e.Refund(context.Background(), r.EscrowID)
			}
			if err == nil {
				outcomes <- x.Status
			}
		}(release)
	}
	wg.Wait()
	close(outcomes)
	if len(outcomes) != 1 {
		t.Fatalf("terminal mutations = %d, want 1", len(outcomes))
	}
}

func TestDirectoryAndAuditAreFrozen(t *testing.T) {
	d := NewInMemoryDirectory()
	p := AgentProfile{ID: "a", Capabilities: []string{"proof"}, Pricing: map[string]Amount{"proof": {1, "LINK", "escrow"}}, Metadata: map[string]string{"required": "yes"}}
	if err := d.Register(p); err != nil {
		t.Fatal(err)
	}
	p.Pricing["proof"] = Amount{999, "BAD", "bad"}
	p.Metadata["required"] = "no"
	got := d.Discover(ServiceQuery{Capability: "proof", SettlementRail: "escrow", RequiredMetadata: map[string]string{"required": "yes"}})
	if len(got) != 1 || got[0].Pricing["proof"].Value != 1 {
		t.Fatalf("registered profile aliased: %#v", got)
	}
	got[0].Metadata["required"] = "mutated"
	if d.Discover(ServiceQuery{Capability: "proof", RequiredMetadata: map[string]string{"required": "yes"}})[0].Metadata["required"] != "yes" {
		t.Fatal("discovery result aliased")
	}
	a := &AuditLog{}
	if err := a.Store(context.Background(), "hash:intent", "intent", "hash", map[string]string{"x": "y"}); err != nil {
		t.Fatal(err)
	}
	entries := a.Entries()
	entries[0].Payload[0] ^= 0xff
	if err := a.VerifyIntegrity(); err != nil {
		t.Fatalf("returned audit payload aliases storage: %v", err)
	}
	if a.Head() == "" {
		t.Fatal("empty audit head")
	}
}

func TestMalformedRegistryAndHashNeverPanic(t *testing.T) {
	r := &sync.Map{}
	w, _ := NewEd25519Wallet(r)
	r.Store(w.Address(), "not a key")
	if w.Verify(w.Address(), []byte("x"), make([]byte, 64)) {
		t.Fatal("malformed key verified")
	}
	e := NewInMemoryEscrow()
	if _, err := e.Lock(context.Background(), SignedIntent{Terms: validTerms(), Hash: "x"}); err == nil {
		t.Fatal("malformed hash accepted")
	}
}

func TestNoVerifierFailsAtConfiguration(t *testing.T) {
	_, err := NewOrchestrator(OrchestratorConfig{Directory: NewInMemoryDirectory(), Escrow: NewInMemoryEscrow(), Reputation: NewInMemoryReputation(), Audit: &AuditLog{}, Wallet: &SafeWallet{}, ExecuteAs: func(context.Context, SignedIntent) ([]byte, map[string]string, error) { return []byte("x"), nil, nil }})
	if !errors.Is(err, ErrVerifierRequired) {
		t.Fatalf("error = %v", err)
	}
}

func TestReputationConcurrentReplayIsIdempotent(t *testing.T) {
	r := NewInMemoryReputation()
	ev := ReputationEvent{EventID: "event-1", AgentID: "seller", IntentHash: "intent", Type: "settled", Delta: 1}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.Update(context.Background(), ev) }()
	}
	wg.Wait()
	s, _ := r.Query(context.Background(), "seller")
	if s.Score != 1 {
		t.Fatalf("score=%d", s.Score)
	}
}

func TestReplayReservationLifecycleAndNamespaces(t *testing.T) {
	s := &InMemoryReplayStore{}
	ctx := context.Background()
	if err := s.Reserve(ctx, "same", "same"); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(ctx, "same", "same"); err != nil {
		t.Fatal(err)
	}
	if err := s.Reserve(ctx, "nonce", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, "nonce", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.Reserve(ctx, "nonce", "other"); !errors.Is(err, ErrIntentReplay) {
		t.Fatalf("committed nonce replay: %v", err)
	}
	if err := s.Reserve(ctx, "other", "hash"); !errors.Is(err, ErrIntentReplay) {
		t.Fatalf("committed hash replay: %v", err)
	}
	var winners atomic.Int32
	race := &InMemoryReplayStore{}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if race.Reserve(ctx, "n", "h") == nil {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("reservation winners=%d", winners.Load())
	}
}

func TestPreLockFailuresDoNotBurnReplayReservation(t *testing.T) {
	t.Run("audit", func(t *testing.T) {
		a := &failOnceAudit{}
		a.failures.Store(1)
		o, q, r, w := transactionHarness(t, a, NewInMemoryEscrow())
		if _, err := o.RunTransaction(context.Background(), q, r, w); err == nil {
			t.Fatal("expected audit failure")
		}
		if got, err := o.RunTransaction(context.Background(), q, r, w); err != nil || got.Status != "released" {
			t.Fatalf("retry=%#v %v", got, err)
		}
	})
	t.Run("escrow", func(t *testing.T) {
		e := &failOnceEscrow{inner: NewInMemoryEscrow()}
		e.failures.Store(1)
		o, q, r, w := transactionHarness(t, &AuditLog{}, e)
		if _, err := o.RunTransaction(context.Background(), q, r, w); err == nil {
			t.Fatal("expected lock failure")
		}
		if got, err := o.RunTransaction(context.Background(), q, r, w); err != nil || got.Status != "released" {
			t.Fatalf("retry=%#v %v", got, err)
		}
	})
}

func TestEscrowRejectsFabricatedDigestAndExpiredAdmission(t *testing.T) {
	terms := validTerms()
	e := NewInMemoryEscrow()
	if _, err := e.Lock(context.Background(), SignedIntent{Terms: terms, Hash: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("fabricated digest locked")
	}
	terms.Timestamp = time.Now().Add(-2 * time.Hour)
	terms.EscrowTerms.Expiration = time.Hour
	h, _ := IntentHash(terms)
	if _, err := e.Lock(context.Background(), SignedIntent{Terms: terms, Hash: h}); !errors.Is(err, ErrIntentExpired) {
		t.Fatalf("expired lock=%v", err)
	}
}

func TestReputationIdempotencyConflict(t *testing.T) {
	r := &InMemoryReputation{}
	base := ReputationEvent{EventID: "one", AgentID: "seller", IntentHash: "intent", Type: "settled", Delta: 1, Reason: "oracle"}
	if err := r.Update(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Delta = 2
	if err := r.Update(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict=%v", err)
	}
}

func TestFinalizationIsResumableAndRejectsConflictingReceipt(t *testing.T) {
	a := &failOnceAudit{}
	a.failures.Store(1)
	o, _, _, _ := transactionHarness(t, a, NewInMemoryEscrow())
	receipt := SettlementReceipt{SettlementID: "settled", EscrowID: "escrow", To: "seller", Amount: Amount{1, "LINK", "escrow"}, Rail: "escrow", Status: "released", Timestamp: time.Now()}
	event := ReputationEvent{EventID: "event", AgentID: "seller", IntentHash: "intent", Type: "settled", Delta: 1}
	if err := o.config.Finalizations.Save(context.Background(), FinalizationRecord{IntentHash: "intent", Receipt: receipt, ReputationEvent: event}); err != nil {
		t.Fatal(err)
	}
	if got, err := o.FinalizeSettlement(context.Background(), "intent"); err == nil || got != receipt {
		t.Fatalf("first finalize=%#v %v", got, err)
	}
	if got, err := o.FinalizeSettlement(context.Background(), "intent"); err != nil || got != receipt {
		t.Fatalf("resume=%#v %v", got, err)
	}
	if _, err := o.FinalizeSettlement(context.Background(), "intent"); err != nil {
		t.Fatal(err)
	}
	conflict := receipt
	conflict.To = "attacker"
	if err := o.config.Finalizations.Save(context.Background(), FinalizationRecord{IntentHash: "intent", Receipt: conflict, ReputationEvent: event}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("receipt conflict=%v", err)
	}
}

func TestExpiryRefundIsBoundedAndPreservesBothErrors(t *testing.T) {
	e := &expiryRefundEscrow{inner: NewInMemoryEscrow()}
	o, q, r, w := transactionHarness(t, &AuditLog{}, e)
	o.config.Timeout = 20 * time.Millisecond
	started := time.Now()
	_, err := o.RunTransaction(context.Background(), q, r, w)
	if !errors.Is(err, ErrEscrowExpired) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("joined expiry error=%v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("unbounded expiry compensation: %s", time.Since(started))
	}
}

func TestVerificationChronologyUsesConfiguredSkew(t *testing.T) {
	now := time.Now().UTC()
	terms := validTerms()
	terms.Timestamp = now
	h, _ := IntentHash(terms)
	eid, _ := digestID("execution", h)
	proof := Proof{IntentHash: h, Executor: terms.Seller, OutputHash: strings.Repeat("a", 64), ExecutionID: eid, Timestamp: now.Add(-time.Minute)}
	result := VerificationResult{Verified: true, Method: "oracle", SatisfiedConditions: []string{"oracle"}, Time: now}
	if err := validateVerification(SignedIntent{Terms: terms, Hash: h}, proof, result, now, 10*time.Second); err == nil {
		t.Fatal("materially predating proof accepted")
	}
	proof.Timestamp = now
	result.Time = now.Add(-time.Minute)
	if err := validateVerification(SignedIntent{Terms: terms, Hash: h}, proof, result, now, 10*time.Second); err == nil {
		t.Fatal("verifier predating proof accepted")
	}
}

func FuzzValidateIntentTerms(f *testing.F) {
	f.Add("proof", "0123456789abcdef")
	f.Fuzz(func(t *testing.T, service, nonce string) {
		x := validTerms()
		x.Service = service
		x.Nonce = nonce
		_ = ValidateIntentTerms(x)
	})
}
func FuzzSignedIntentVerification(f *testing.F) {
	f.Add("bad", []byte("sig"))
	f.Fuzz(func(t *testing.T, h string, s []byte) {
		_ = VerifySignedIntent(SignedIntent{Terms: validTerms(), Hash: h, BuyerSignature: s, SellerSignature: s}, NewSafeWallet(nil))
	})
}
func FuzzEscrowTransitions(f *testing.F) {
	f.Add("id")
	f.Fuzz(func(t *testing.T, id string) {
		e := NewInMemoryEscrow()
		_, _ = e.Release(context.Background(), id)
		_, _ = e.Refund(context.Background(), id)
	})
}
func FuzzMalformedRegistry(f *testing.F) {
	f.Add([]byte("key"), []byte("sig"))
	f.Fuzz(func(t *testing.T, key, sig []byte) {
		r := &sync.Map{}
		w, _ := NewEd25519Wallet(r)
		r.Store(w.Address(), key)
		_ = w.Verify(w.Address(), []byte("payload"), sig)
	})
}
func FuzzAuditIntegrity(f *testing.F) {
	f.Add("kind", "ref", []byte("payload"))
	f.Fuzz(func(t *testing.T, k, r string, p []byte) {
		a := &AuditLog{}
		_ = a.Store(context.Background(), r+":"+k, k, r, p)
		_ = a.VerifyIntegrity()
	})
}
func FuzzReplayReservations(f *testing.F) {
	f.Add("nonce", "hash")
	f.Fuzz(func(t *testing.T, n, h string) {
		s := &InMemoryReplayStore{}
		ctx := context.Background()
		_ = s.Reserve(ctx, n, h)
		_ = s.Commit(ctx, n, h)
		_ = s.Release(ctx, n, h)
	})
}
func FuzzReputationIdempotency(f *testing.F) {
	f.Add("event", "agent", "intent", int64(1))
	f.Fuzz(func(t *testing.T, id, agent, intent string, delta int64) {
		r := &InMemoryReputation{}
		e := ReputationEvent{EventID: id, AgentID: agent, IntentHash: intent, Type: "event", Delta: delta}
		_ = r.Update(context.Background(), e)
		e.Delta++
		_ = r.Update(context.Background(), e)
	})
}
