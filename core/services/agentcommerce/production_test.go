package agentcommerce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAtomicAmountUint256(t *testing.T) {
	max := maxUint256.String()
	for _, s := range []string{"0", "1", max} {
		a, err := ParseAtomicAmount(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		if a.String() != s {
			t.Fatalf("not canonical: %q", a)
		}
		b, err := json.Marshal(a)
		if err != nil || string(b) != `"`+s+`"` {
			t.Fatalf("JSON = %s, %v", b, err)
		}
		var round AtomicAmount
		if err = json.Unmarshal(b, &round); err != nil || round != a {
			t.Fatalf("round trip: %+v %v", round, err)
		}
	}
	over := new(big.Int).Add(maxUint256, big.NewInt(1)).String()
	bad := []string{"", "+1", "-1", "00", "01", "1.0", "1e2", " 1", "1 ", over, strings.Repeat("9", 10000)}
	for _, s := range bad {
		if _, err := ParseAtomicAmount(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if _, err := json.Marshal(AtomicAmount{}); err == nil {
		t.Fatal("zero value must not serialize")
	}
}

func TestAssetAmountIdentityAndComparison(t *testing.T) {
	one, _ := ParseAtomicAmount("1")
	two, _ := ParseAtomicAmount("2")
	a := AssetAmountV2{one, "LINK", "evm"}
	b := AssetAmountV2{two, "LINK", "evm"}
	if got, err := a.Compare(b); err != nil || got >= 0 {
		t.Fatalf("comparison = %d, %v", got, err)
	}
	b.Currency = "ETH"
	if _, err := a.Compare(b); err == nil {
		t.Fatal("asset mismatch accepted")
	}
}

func TestSettlementIdempotencyKey(t *testing.T) {
	h1 := strings.Repeat("01", 32)
	h2 := strings.Repeat("02", 32)
	a, _ := SettlementIdempotencyKey(h1, "escrow")
	b, _ := SettlementIdempotencyKey(h1, "escrow")
	c, _ := SettlementIdempotencyKey(h2, "escrow")
	if a != b || a == c || len(a) != 64 {
		t.Fatalf("keys %q %q %q", a, b, c)
	}
}

func TestSignedSettlementV2CommitsExactUint256(t *testing.T) {
	amount, _ := ParseAtomicAmount(maxUint256.String())
	h := strings.Repeat("01", 32)
	key, _ := SettlementIdempotencyKey(h, "escrow")
	terms := SignedSettlementTermsV2{ProtocolVersion: "ACP/settlement/v2", IntentHash: h, EscrowID: "escrow", ChainID: "11155111", Destination: "0x0000000000000000000000000000000000000001", Token: "0x0000000000000000000000000000000000000002", Amount: AssetAmountV2{Atomic: amount, Currency: "LINK", Rail: "evm"}, IdempotencyKey: key}
	a, err := SettlementAuthorizationDigest(terms)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SettlementAuthorizationDigest(terms)
	if err != nil || !strings.EqualFold(fmt.Sprintf("%x", a), fmt.Sprintf("%x", b)) {
		t.Fatalf("digest mismatch: %v", err)
	}
	req, err := terms.Request()
	if err != nil || req.Amount.String() != maxUint256.String() {
		t.Fatalf("request=%+v err=%v", req, err)
	}
	tampered := terms
	tampered.Amount.Atomic, _ = ParseAtomicAmount("1")
	c, _ := SettlementAuthorizationDigest(tampered)
	if string(a) == string(c) {
		t.Fatal("amount not committed")
	}
}

func TestSepoliaDryRunGate(t *testing.T) {
	good := SepoliaConfig{ChainID: "11155111", FromAddress: "0x0000000000000000000000000000000000000001"}
	if err := good.ValidateDryRun(); err != nil {
		t.Fatal(err)
	}
	good.Broadcast = true
	if err := good.ValidateDryRun(); err == nil {
		t.Fatal("broadcast accepted by dry-run gate")
	}
}

func TestPreExecutionValidationBindsIntent(t *testing.T) {
	terms := validTerms()
	h, err := IntentHash(terms)
	if err != nil {
		t.Fatal(err)
	}
	r := ReplayRecord{SchemaVersion: 1, Nonce: terms.Nonce, IntentHash: h, Version: 1}
	e := EscrowRecord{SchemaVersion: 1, EscrowID: "escrow", Nonce: terms.Nonce, IntentHash: h, Intent: SignedIntent{Terms: terms, Hash: h}, Version: 1}
	if err = validatePreExecutionRecords(r, e); err != nil {
		t.Fatal(err)
	}
	e.IntentHash = strings.Repeat("02", 32)
	if err = validatePreExecutionRecords(r, e); err == nil {
		t.Fatal("mismatch accepted")
	}
}

type memorySettlementAdapter struct {
	mu      sync.Mutex
	result  SettlementResult
	settles int
}

func (m *memorySettlementAdapter) Lookup(context.Context, string) (SettlementResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.result, nil
}
func (m *memorySettlementAdapter) Settle(context.Context, SettlementRequest, string) (SettlementResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settles++
	m.result = SettlementResult{Outcome: SettlementPending, ExternalID: "tx"}
	return m.result, nil
}

func TestSettlementReconciliationNeverBlindlyResubmits(t *testing.T) {
	req := SettlementRequest{IntentHash: strings.Repeat("01", 32), EscrowID: "escrow"}
	for _, state := range []SettlementOutcome{SettlementUnknown, SettlementSubmitted, SettlementPending, SettlementConfirmed} {
		a := &memorySettlementAdapter{result: SettlementResult{Outcome: state, ExternalID: "tx"}}
		_, err := ReconcileSettlement(context.Background(), a, req)
		if state == SettlementConfirmed && err != nil {
			t.Fatal(err)
		}
		if state != SettlementConfirmed && !errors.Is(err, ErrSettlementPending) {
			t.Fatalf("%s: %v", state, err)
		}
		if a.settles != 0 {
			t.Fatalf("%s was resubmitted", state)
		}
	}
	a := &memorySettlementAdapter{result: SettlementResult{Outcome: SettlementReverted}}
	if _, err := ReconcileSettlement(context.Background(), a, req); err != nil || a.settles != 1 {
		t.Fatalf("confirmed failure: %v, %d", err, a.settles)
	}
}

func TestAuditIdempotencyConcurrent(t *testing.T) {
	var log AuditLog
	ctx := context.Background()
	payload := map[string]string{"status": "confirmed"}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := log.Store(ctx, "intent:settlement", "settlement", "intent", payload); err != nil {
				t.Errorf("store: %v", err)
			}
		}()
	}
	wg.Wait()
	if len(log.Entries()) != 1 {
		t.Fatalf("entries = %d", len(log.Entries()))
	}
	if err := log.Store(ctx, "intent:settlement", "settlement", "intent", map[string]string{"status": "other"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict = %v", err)
	}
}

func TestFinalizationOptimisticMonotonicity(t *testing.T) {
	var s InMemoryFinalizationStore
	r := FinalizationRecord{IntentHash: "intent", Receipt: SettlementReceipt{SettlementID: "settled"}, ReputationEvent: ReputationEvent{EventID: "event"}}
	if err := s.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r, _ = s.Get(context.Background(), "intent")
	a := r
	a.AuditComplete = true
	if err := s.CompareAndSwap(context.Background(), a, r.Version); err != nil {
		t.Fatal(err)
	}
	b := r
	b.ReputationComplete = true
	if err := s.CompareAndSwap(context.Background(), b, r.Version); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale CAS = %v", err)
	}
	got, _ := s.Get(context.Background(), "intent")
	if !got.AuditComplete || got.ReputationComplete {
		t.Fatalf("rollback/overwrite: %+v", got)
	}
}

func TestConcurrentFinalizersCreateOneLogicalMutation(t *testing.T) {
	o, _, _, _ := transactionHarness(t, &AuditLog{}, NewInMemoryEscrow())
	r := FinalizationRecord{IntentHash: "intent", Receipt: SettlementReceipt{SettlementID: "settled"}, ReputationEvent: ReputationEvent{EventID: "event", AgentID: "seller", IntentHash: "intent", Type: "settled", Delta: 1}}
	if err := o.config.Finalizations.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := o.FinalizeSettlement(context.Background(), "intent"); err != nil {
				t.Errorf("finalize: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := len(o.config.Audit.(*AuditLog).Entries()); got != 1 {
		t.Fatalf("audit entries = %d", got)
	}
	score, err := o.config.Reputation.Query(context.Background(), "seller")
	if err != nil || score.Score != 1 {
		t.Fatalf("score=%+v err=%v", score, err)
	}
	final, _ := o.config.Finalizations.Get(context.Background(), "intent")
	if !final.Complete {
		t.Fatalf("not complete: %+v", final)
	}
}

func TestZeroValueStoresConcurrentRace(t *testing.T) {
	var replay InMemoryReplayStore
	var finals InMemoryFinalizationStore
	var audit AuditLog
	var rep InMemoryReputation
	var anchor InMemoryAuditAnchor
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := big.NewInt(int64(i + 1)).String()
			_ = replay.Reserve(ctx, "nonce"+id, "hash"+id)
			_ = finals.Save(ctx, FinalizationRecord{IntentHash: "h" + id, Receipt: SettlementReceipt{SettlementID: "s" + id}})
			_ = audit.Store(ctx, "k"+id, "kind", "ref", id)
			_ = rep.Update(ctx, ReputationEvent{EventID: "e" + id, AgentID: "a", IntentHash: "h", Type: "settled", Delta: 1})
			_ = anchor.Anchor(ctx, AuditAnchorRecord{SchemaVersion: 1, Sequence: uint64(i + 1), Head: "head" + id})
		}()
	}
	wg.Wait()
}

type mockEVMTx struct {
	calls  atomic.Int32
	amount *big.Int
}

func (m *mockEVMTx) SubmitTokenTransfer(_ context.Context, _, _, _ string, n *big.Int, _ string) (string, error) {
	m.calls.Add(1)
	m.amount = new(big.Int).Set(n)
	return "0xtx", nil
}
func (*mockEVMTx) LookupTransfer(context.Context, string, string) (SettlementResult, error) {
	return SettlementResult{Outcome: SettlementPending}, nil
}
func TestEVMSettlementAdapterUsesUint256(t *testing.T) {
	a, _ := ParseAtomicAmount(maxUint256.String())
	tx := new(mockEVMTx)
	evm := EVMSettlementAdapter{ChainID: "1", Submitter: tx}
	r, err := evm.Settle(context.Background(), SettlementRequest{ChainID: "1", Destination: "0x0000000000000000000000000000000000000001", Token: "0x0000000000000000000000000000000000000002", Amount: a}, "key")
	if err != nil || r.Outcome != SettlementPending || tx.amount.Cmp(maxUint256) != 0 {
		t.Fatalf("result=%+v amount=%v err=%v", r, tx.amount, err)
	}
}

func TestAuditAnchorRejectsRollback(t *testing.T) {
	var a InMemoryAuditAnchor
	ctx := context.Background()
	now := time.Now()
	if err := a.Anchor(ctx, AuditAnchorRecord{SchemaVersion: 1, Sequence: 1, Head: "h1", AnchoredAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := a.Anchor(ctx, AuditAnchorRecord{SchemaVersion: 1, Sequence: 2, Head: "h2", PreviousHead: "wrong"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("rollback=%v", err)
	}
}
