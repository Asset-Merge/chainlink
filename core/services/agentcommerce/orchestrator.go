package agentcommerce

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

type ServiceExecutor func(context.Context, SignedIntent) ([]byte, map[string]string, error)
type ProofVerifier func(context.Context, SignedIntent, Proof) (VerificationResult, error)
type WalletApprover interface {
	Approve(context.Context, IntentTerms) (bool, error)
}
type ReplayStore interface {
	Reserve(context.Context, string, string) error
	Commit(context.Context, string, string) error
	Release(context.Context, string, string) error
}
type InMemoryReplayStore struct {
	mu              sync.Mutex
	reservedNonces  map[string]string
	reservedHashes  map[string]string
	committedNonces map[string]string
	committedHashes map[string]string
}

func NewInMemoryReplayStore() *InMemoryReplayStore {
	return &InMemoryReplayStore{}
}
func (s *InMemoryReplayStore) init() {
	if s.reservedNonces == nil {
		s.reservedNonces = map[string]string{}
	}
	if s.reservedHashes == nil {
		s.reservedHashes = map[string]string{}
	}
	if s.committedNonces == nil {
		s.committedNonces = map[string]string{}
	}
	if s.committedHashes == nil {
		s.committedHashes = map[string]string{}
	}
}
func (s *InMemoryReplayStore) Reserve(ctx context.Context, nonce, hash string) error {
	if s == nil {
		return errors.New("nil replay store")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if nonce == "" || hash == "" {
		return errors.New("nonce and intent hash required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	if _, ok := s.reservedNonces[nonce]; ok {
		return ErrIntentReplay
	}
	if _, ok := s.reservedHashes[hash]; ok {
		return ErrIntentReplay
	}
	if _, ok := s.committedNonces[nonce]; ok {
		return ErrIntentReplay
	}
	if _, ok := s.committedHashes[hash]; ok {
		return ErrIntentReplay
	}
	s.reservedNonces[nonce], s.reservedHashes[hash] = hash, nonce
	return nil
}
func (s *InMemoryReplayStore) Commit(ctx context.Context, nonce, hash string) error {
	if s == nil {
		return errors.New("nil replay store")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	if s.committedNonces[nonce] == hash && s.committedHashes[hash] == nonce {
		return nil
	}
	if s.reservedNonces[nonce] != hash || s.reservedHashes[hash] != nonce {
		return errors.New("replay reservation not held")
	}
	delete(s.reservedNonces, nonce)
	delete(s.reservedHashes, hash)
	s.committedNonces[nonce], s.committedHashes[hash] = hash, nonce
	return nil
}
func (s *InMemoryReplayStore) Release(ctx context.Context, nonce, hash string) error {
	if s == nil {
		return errors.New("nil replay store")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	if s.committedNonces[nonce] == hash || s.committedHashes[hash] == nonce {
		return ErrIntentReplay
	}
	if got, ok := s.reservedNonces[nonce]; ok && got != hash {
		return ErrIdempotencyConflict
	}
	if got, ok := s.reservedHashes[hash]; ok && got != nonce {
		return ErrIdempotencyConflict
	}
	delete(s.reservedNonces, nonce)
	delete(s.reservedHashes, hash)
	return nil
}

type AuditStore interface {
	Store(context.Context, string, string, string, any) error
}
type FinalizationRecord struct {
	SchemaVersion      int
	Version            uint64
	IntentHash         string
	Receipt            SettlementReceipt
	ReputationEvent    ReputationEvent
	AuditComplete      bool
	ReputationComplete bool
	Complete           bool
}
type FinalizationStore interface {
	Save(context.Context, FinalizationRecord) error
	Get(context.Context, string) (FinalizationRecord, error)
	CompareAndSwap(context.Context, FinalizationRecord, uint64) error
}
type InMemoryFinalizationStore struct {
	mu      sync.Mutex
	records map[string]FinalizationRecord
}

func NewInMemoryFinalizationStore() *InMemoryFinalizationStore { return &InMemoryFinalizationStore{} }
func (s *InMemoryFinalizationStore) Save(ctx context.Context, r FinalizationRecord) error {
	if s == nil {
		return errors.New("nil finalization store")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.IntentHash == "" || r.Receipt.SettlementID == "" {
		return errors.New("invalid finalization record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = map[string]FinalizationRecord{}
	}
	if old, ok := s.records[r.IntentHash]; ok {
		if old.Receipt != r.Receipt || old.ReputationEvent != r.ReputationEvent {
			return ErrIdempotencyConflict
		}
		return nil
	}
	if r.SchemaVersion == 0 {
		r.SchemaVersion = persistenceSchemaV1
	}
	if r.SchemaVersion != persistenceSchemaV1 {
		return errors.New("unsupported finalization schema")
	}
	r.Version = 1
	s.records[r.IntentHash] = r
	return nil
}
func (s *InMemoryFinalizationStore) Get(ctx context.Context, h string) (FinalizationRecord, error) {
	if s == nil {
		return FinalizationRecord{}, errors.New("nil finalization store")
	}
	if err := ctx.Err(); err != nil {
		return FinalizationRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[h]
	if !ok {
		return r, errors.New("finalization not found")
	}
	return r, nil
}
func (s *InMemoryFinalizationStore) CompareAndSwap(ctx context.Context, next FinalizationRecord, expected uint64) error {
	if s == nil {
		return errors.New("nil finalization store")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[next.IntentHash]
	if !ok {
		return errors.New("finalization not found")
	}
	if r.Version != expected {
		return ErrVersionConflict
	}
	if r.Receipt != next.Receipt || r.ReputationEvent != next.ReputationEvent ||
		(r.AuditComplete && !next.AuditComplete) || (r.ReputationComplete && !next.ReputationComplete) {
		return ErrIdempotencyConflict
	}
	next.SchemaVersion = persistenceSchemaV1
	next.Version = expected + 1
	next.Complete = next.AuditComplete && next.ReputationComplete
	s.records[next.IntentHash] = next
	return nil
}

type OrchestratorConfig struct {
	Directory        *InMemoryDirectory
	Escrow           Escrow
	Reputation       Reputation
	Audit            AuditStore
	Wallet           Wallet
	Policy           Policy
	Approver         WalletApprover
	Replay           ReplayStore
	Finalizations    FinalizationStore
	VerifyWith       ProofVerifier
	ExecuteAs        ServiceExecutor
	Timeout          time.Duration
	Now              func() time.Time
	AllowedClockSkew time.Duration
	MaxIntentTTL     time.Duration
}
type Orchestrator struct{ config OrchestratorConfig }

func NewOrchestrator(c OrchestratorConfig) (*Orchestrator, error) {
	if isNilDependency(c.Directory) || isNilDependency(c.Escrow) || isNilDependency(c.Reputation) || isNilDependency(c.Audit) || isNilDependency(c.Wallet) || c.ExecuteAs == nil {
		return nil, errors.New("directory, escrow, reputation, audit, buyer wallet, and executor are required")
	}
	if c.VerifyWith == nil {
		return nil, ErrVerifierRequired
	}
	if c.Policy.RequireWalletApproval && isNilDependency(c.Approver) {
		return nil, fmt.Errorf("%w: approver required", ErrPolicyDenied)
	}
	if c.Replay == nil {
		c.Replay = NewInMemoryReplayStore()
	}
	if c.Finalizations == nil {
		c.Finalizations = NewInMemoryFinalizationStore()
	}
	if isNilDependency(c.Replay) || isNilDependency(c.Finalizations) {
		return nil, errors.New("replay and finalization stores must not be typed nil")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.AllowedClockSkew <= 0 {
		c.AllowedClockSkew = AllowedSkew
	}
	if c.MaxIntentTTL <= 0 {
		c.MaxIntentTTL = MaxIntentTTL
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	return &Orchestrator{c}, nil
}
func isNilDependency(v any) bool {
	if v == nil {
		return true
	}
	x := reflect.ValueOf(v)
	switch x.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return x.IsNil()
	}
	return false
}
func (o *Orchestrator) RunTransaction(parent context.Context, q ServiceQuery, req ServiceRequest, sellerWallet Wallet) (receipt SettlementReceipt, err error) {
	if err = o.validateInputs(q, req, sellerWallet); err != nil {
		return receipt, err
	}
	ctx, cancel := context.WithTimeout(parent, o.config.Timeout)
	defer cancel()
	if err = ctx.Err(); err != nil {
		return receipt, err
	}
	sellers := o.config.Directory.Discover(q)
	if len(sellers) == 0 {
		return receipt, errors.New("no matching seller")
	}
	seller := sellers[0]
	if sellerWallet.Address() != seller.ID {
		return receipt, ErrSellerMismatch
	}
	price, ok := seller.Pricing[q.Capability]
	if !ok {
		return receipt, errors.New("selected seller has no validated price")
	}
	req = cloneRequest(req)
	if req.Nonce == "" {
		req.Nonce, err = randomNonce()
		if err != nil {
			return receipt, err
		}
	}
	now := o.config.Now().UTC()
	terms := IntentTerms{ServiceRequest: req, Price: price, Buyer: o.config.Wallet.Address(), Seller: seller.ID, Timestamp: now}
	if err = EvaluatePolicy(o.config.Policy, seller, terms); err != nil {
		return receipt, err
	}
	if o.config.Policy.RequireWalletApproval {
		var yes bool
		yes, err = o.config.Approver.Approve(ctx, cloneTerms(terms))
		if err != nil || !yes {
			if err == nil {
				err = ErrPolicyDenied
			}
			return receipt, fmt.Errorf("%w: wallet approval", err)
		}
	}
	intent, err := SignIntent(terms, o.config.Wallet, sellerWallet)
	if err != nil {
		return receipt, err
	}
	if err = VerifySignedIntent(intent, o.config.Wallet); err != nil {
		return receipt, err
	}
	if err = o.validateFresh(intent.Terms, now); err != nil {
		return receipt, err
	}
	if err = o.config.Replay.Reserve(ctx, intent.Terms.Nonce, intent.Hash); err != nil {
		return receipt, err
	}
	lockedReplay := false
	defer func() {
		if !lockedReplay {
			releaseCtx, cancel := context.WithTimeout(context.Background(), o.config.Timeout)
			defer cancel()
			if releaseErr := o.config.Replay.Release(releaseCtx, intent.Terms.Nonce, intent.Hash); releaseErr != nil && !errors.Is(releaseErr, ErrIntentReplay) {
				err = errors.Join(err, releaseErr)
			}
		}
	}()
	if err = o.config.Audit.Store(ctx, intent.Hash+":intent", "intent", intent.Hash, intent); err != nil {
		return receipt, err
	}
	if err = ctx.Err(); err != nil {
		return receipt, err
	}
	locked, err := o.config.Escrow.Lock(ctx, intent)
	if err != nil {
		return receipt, fmt.Errorf("escrow lock: %w", err)
	}
	lockedReplay = true
	if err = o.config.Replay.Commit(ctx, intent.Terms.Nonce, intent.Hash); err != nil {
		return receipt, fmt.Errorf("commit replay protection: %w", err)
	}
	settled := false
	defer func() {
		if err != nil && !settled {
			compCtx, cancel := context.WithTimeout(context.Background(), o.config.Timeout)
			defer cancel()
			_, refundErr := o.config.Escrow.Refund(compCtx, locked.EscrowID)
			if refundErr != nil && !errors.Is(refundErr, ErrEscrowAlreadySettled) {
				err = errors.Join(err, fmt.Errorf("compensation refund: %w", refundErr))
			}
		}
	}()
	if err = o.config.Audit.Store(ctx, intent.Hash+":escrow", "escrow", intent.Hash, locked); err != nil {
		return receipt, err
	}
	proof, err := o.execute(ctx, intent)
	if err != nil {
		return receipt, fmt.Errorf("execution: %w", err)
	}
	if err = o.config.Audit.Store(ctx, intent.Hash+":proof", "proof", intent.Hash, proof); err != nil {
		return receipt, err
	}
	result, err := o.verify(ctx, intent, proof)
	if err != nil {
		return receipt, fmt.Errorf("verification: %w", err)
	}
	if err = validateVerification(intent, proof, result, o.config.Now().UTC(), o.config.AllowedClockSkew); err != nil {
		return receipt, err
	}
	if err = o.config.Audit.Store(ctx, intent.Hash+":verification", "verification", intent.Hash, result); err != nil {
		return receipt, err
	}
	if !result.Verified {
		receipt, err = o.config.Escrow.Refund(ctx, locked.EscrowID)
		if err != nil {
			return receipt, err
		}
		settled = true
	} else {
		receipt, err = o.config.Escrow.Release(ctx, locked.EscrowID)
		if errors.Is(err, ErrEscrowExpired) {
			expiryErr := err
			compCtx, cancel := context.WithTimeout(context.Background(), o.config.Timeout)
			receipt, err = o.config.Escrow.Refund(compCtx, locked.EscrowID)
			cancel()
			if err == nil {
				settled = true
				return receipt, expiryErr
			}
			return receipt, errors.Join(expiryErr, fmt.Errorf("expiry refund: %w", err))
		}
		if err != nil {
			return receipt, err
		}
		settled = true
	}
	typ, delta := "failed", int64(-1)
	if result.Verified {
		typ, delta = "settled", 1
	}
	ev := ReputationEvent{EventID: intent.Hash + ":seller:" + typ, AgentID: seller.ID, IntentHash: intent.Hash, Type: typ, Delta: delta, Reason: result.Method}
	if err = o.config.Finalizations.Save(ctx, FinalizationRecord{IntentHash: intent.Hash, Receipt: receipt, ReputationEvent: ev}); err != nil {
		return receipt, fmt.Errorf("persist finalization: %w", err)
	}
	_, err = o.FinalizeSettlement(ctx, intent.Hash)
	return receipt, err
}

// FinalizeSettlement resumes the idempotent post-settlement outbox without
// executing or settling the intent again.
func (o *Orchestrator) FinalizeSettlement(ctx context.Context, intentHash string) (SettlementReceipt, error) {
	r, err := o.config.Finalizations.Get(ctx, intentHash)
	if err != nil {
		return SettlementReceipt{}, err
	}
	if !r.AuditComplete {
		if err = o.config.Audit.Store(ctx, intentHash+":settlement", "settlement", intentHash, r.Receipt); err != nil {
			return r.Receipt, fmt.Errorf("post-settlement audit: %w", err)
		}
		next := r
		next.AuditComplete = true
		if err = o.config.Finalizations.CompareAndSwap(ctx, next, r.Version); err != nil && !errors.Is(err, ErrVersionConflict) {
			return r.Receipt, err
		}
	}
	r, err = o.config.Finalizations.Get(ctx, intentHash)
	if err != nil {
		return SettlementReceipt{}, err
	}
	if !r.ReputationComplete {
		if err = o.config.Reputation.Update(ctx, r.ReputationEvent); err != nil {
			return r.Receipt, fmt.Errorf("post-settlement reputation: %w", err)
		}
		next := r
		next.ReputationComplete = true
		if err = o.config.Finalizations.CompareAndSwap(ctx, next, r.Version); err != nil && !errors.Is(err, ErrVersionConflict) {
			return r.Receipt, err
		}
	}
	return r.Receipt, nil
}
func (o *Orchestrator) validateInputs(q ServiceQuery, r ServiceRequest, w Wallet) error {
	if w == nil {
		return errors.New("seller wallet required")
	}
	if q.Capability == "" || len(q.Capability) > 128 {
		return errors.New("invalid capability")
	}
	if r.Service != q.Capability {
		return ErrServiceMismatch
	}
	if q.SettlementRail == "" || q.MaxPrice.Value < 0 {
		return errors.New("invalid query price/rail")
	}
	if q.MaxPrice.Value > 0 && (q.MaxPrice.Currency == "" || q.MaxPrice.Rail == "") {
		return errors.New("max price requires currency and rail")
	}
	if q.MaxPrice.Rail != "" && q.MaxPrice.Rail != q.SettlementRail {
		return errors.New("query rail mismatch")
	}
	return nil
}
func (o *Orchestrator) validateFresh(t IntentTerms, now time.Time) error {
	if t.Timestamp.After(now.Add(o.config.AllowedClockSkew)) {
		return errors.New("intent issued too far in future")
	}
	if t.EscrowTerms.Expiration > o.config.MaxIntentTTL {
		return errors.New("intent TTL exceeds maximum")
	}
	if !now.Before(t.Timestamp.Add(t.EscrowTerms.Expiration)) {
		return ErrIntentExpired
	}
	return nil
}
func (o *Orchestrator) execute(ctx context.Context, i SignedIntent) (Proof, error) {
	if err := ctx.Err(); err != nil {
		return Proof{}, err
	}
	out, md, err := o.config.ExecuteAs(ctx, i)
	if err != nil {
		return Proof{}, err
	}
	if len(out) == 0 {
		return Proof{}, errors.New("empty executor output")
	}
	h := sha256.Sum256(out)
	eid, err := digestID("execution", i.Hash)
	if err != nil {
		return Proof{}, err
	}
	return Proof{IntentHash: i.Hash, Executor: i.Terms.Seller, OutputHash: hex.EncodeToString(h[:]), Timestamp: o.config.Now().UTC(), ExecutionID: eid, Metadata: cloneMap(md)}, nil
}
func (o *Orchestrator) verify(ctx context.Context, i SignedIntent, p Proof) (VerificationResult, error) {
	if err := ctx.Err(); err != nil {
		return VerificationResult{}, err
	}
	return o.config.VerifyWith(ctx, i, p)
}
func validateVerification(i SignedIntent, p Proof, r VerificationResult, now time.Time, skew time.Duration) error {
	if p.IntentHash != i.Hash || p.Executor != i.Terms.Seller {
		return errors.New("proof is not bound to intent and seller")
	}
	if _, err := digestID("execution", i.Hash); err != nil {
		return err
	}
	want, _ := digestID("execution", i.Hash)
	if p.ExecutionID != want {
		return errors.New("invalid execution ID")
	}
	b, err := hex.DecodeString(p.OutputHash)
	if err != nil || len(b) != sha256.Size {
		return errors.New("malformed output hash")
	}
	if p.Timestamp.IsZero() || p.Timestamp.Before(i.Terms.Timestamp.Add(-skew)) || p.Timestamp.After(now.Add(skew)) {
		return errors.New("invalid proof timestamp")
	}
	if !r.Verified {
		return nil
	}
	if r.Method == "" || r.Time.IsZero() || r.Time.Before(p.Timestamp.Add(-skew)) || r.Time.After(now.Add(skew)) {
		return errors.New("invalid verifier result")
	}
	have := map[string]bool{}
	for _, c := range r.SatisfiedConditions {
		have[c] = true
	}
	for _, c := range i.Terms.EscrowTerms.ReleaseConditions {
		if !have[c] {
			return fmt.Errorf("release condition %q not verified", c)
		}
	}
	return nil
}
func randomNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func cloneRequest(r ServiceRequest) ServiceRequest {
	r.Deliverables = append([]string(nil), r.Deliverables...)
	r.EscrowTerms.ReleaseConditions = append([]string(nil), r.EscrowTerms.ReleaseConditions...)
	r.Metadata = cloneMap(r.Metadata)
	return r
}
