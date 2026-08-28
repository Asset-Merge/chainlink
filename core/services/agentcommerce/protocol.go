// Package agentcommerce implements the Agent Commerce Protocol (ACP). Its
// in-memory stores are concurrency-safe reference implementations, not durable
// payment infrastructure. In particular, AuditLog must be durably stored or
// externally anchored to be tamper-proof.
package agentcommerce

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	signingDomain = "CHAINLINK_ACP/intent/v1"
	auditDomain   = "CHAINLINK_ACP/audit/v1"
	MaxIntentTTL  = 24 * time.Hour
	AllowedSkew   = 2 * time.Minute
)

var (
	ErrVerifierRequired     = errors.New("proof verifier required")
	ErrIntentExpired        = errors.New("intent expired")
	ErrIntentReplay         = errors.New("intent replay")
	ErrSellerMismatch       = errors.New("seller identity mismatch")
	ErrServiceMismatch      = errors.New("service does not match capability")
	ErrEscrowAlreadySettled = errors.New("escrow terminal-state conflict")
	ErrEscrowExpired        = errors.New("escrow expired")
	ErrPolicyDenied         = errors.New("policy denied")
	ErrIdempotencyConflict  = errors.New("idempotency key conflicts with existing payload")
)

type Wallet interface {
	Address() string
	Sign([]byte) ([]byte, error)
	Verify(string, []byte, []byte) bool
}
type Agent interface {
	Discover(context.Context, ServiceQuery) ([]AgentProfile, error)
	Negotiate(context.Context, AgentProfile, ServiceRequest) (IntentTerms, error)
	Execute(context.Context, SignedIntent) (Proof, error)
	Verify(context.Context, SignedIntent, Proof) (VerificationResult, error)
	Settle(context.Context, SignedIntent, VerificationResult) (SettlementReceipt, error)
}
type Escrow interface {
	Lock(context.Context, SignedIntent) (EscrowReceipt, error)
	Release(context.Context, string) (SettlementReceipt, error)
	Refund(context.Context, string) (SettlementReceipt, error)
}
type Settlement interface {
	Send(context.Context, SettlementInstruction) (SettlementReceipt, error)
	Receive(context.Context, SettlementReceipt) error
}
type Reputation interface {
	Update(context.Context, ReputationEvent) error
	Query(context.Context, string) (ReputationScore, error)
}

type AgentProfile struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Capabilities []string          `json:"capabilities"`
	Pricing      map[string]Amount `json:"pricing"`
	Reputation   ReputationScore   `json:"reputation"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Amount is an integer number of atomic units. Floating point money is forbidden.
type Amount struct {
	Value    int64  `json:"value"`
	Currency string `json:"currency"`
	Rail     string `json:"rail"`
}
type ServiceQuery struct {
	Capability       string
	MaxPrice         Amount
	MinReputation    int64
	SettlementRail   string
	RequiredMetadata map[string]string
}
type ServiceRequest struct {
	Service         string            `json:"service"`
	SLA             string            `json:"sla"`
	Deliverables    []string          `json:"deliverables"`
	SettlementChain string            `json:"settlement_chain"`
	EscrowTerms     EscrowTerms       `json:"escrow_terms"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	Nonce           string            `json:"nonce,omitempty"`
}
type EscrowTerms struct {
	ReleaseConditions []string      `json:"release_conditions"`
	Expiration        time.Duration `json:"expiration"`
}
type IntentTerms struct {
	ServiceRequest
	Price     Amount    `json:"price"`
	Buyer     string    `json:"buyer"`
	Seller    string    `json:"seller"`
	Timestamp time.Time `json:"timestamp"`
}
type SignedIntent struct {
	Terms           IntentTerms `json:"terms"`
	Hash            string      `json:"hash"`
	BuyerSignature  []byte      `json:"buyer_signature"`
	SellerSignature []byte      `json:"seller_signature"`
}
type Proof struct {
	IntentHash  string            `json:"intent_hash"`
	Executor    string            `json:"executor"`
	OutputHash  string            `json:"output_hash"`
	Timestamp   time.Time         `json:"timestamp"`
	ExecutionID string            `json:"execution_id"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
type VerificationResult struct {
	Verified            bool      `json:"verified"`
	Method              string    `json:"method"`
	SatisfiedConditions []string  `json:"satisfied_conditions"`
	Reason              string    `json:"reason,omitempty"`
	Time                time.Time `json:"time"`
}
type EscrowReceipt struct {
	EscrowID   string    `json:"escrow_id"`
	IntentHash string    `json:"intent_hash"`
	Buyer      string    `json:"buyer"`
	Seller     string    `json:"seller"`
	Amount     Amount    `json:"amount"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type SettlementInstruction struct {
	EscrowID string
	To       string
	Amount   Amount
	Rail     string
}
type SettlementReceipt struct {
	SettlementID string    `json:"settlement_id"`
	EscrowID     string    `json:"escrow_id"`
	To           string    `json:"to"`
	Amount       Amount    `json:"amount"`
	Rail         string    `json:"rail"`
	Status       string    `json:"status"`
	Timestamp    time.Time `json:"timestamp"`
}
type ReputationEvent struct {
	EventID    string
	AgentID    string
	IntentHash string
	Delta      int64
	Type       string
	Reason     string
}
type ReputationScore struct {
	AgentID    string `json:"agent_id"`
	Successful int64  `json:"successful"`
	Disputed   int64  `json:"disputed"`
	Score      int64  `json:"score"`
}
type AuditEntry struct {
	Sequence     uint64    `json:"sequence"`
	Kind         string    `json:"kind"`
	Ref          string    `json:"ref"`
	Payload      []byte    `json:"payload"`
	PayloadHash  string    `json:"payload_hash"`
	PreviousHash string    `json:"previous_hash,omitempty"`
	EntryHash    string    `json:"entry_hash"`
	Timestamp    time.Time `json:"timestamp"`
}
type Policy struct {
	MaxSpend              int64
	AllowedCurrencies     []string
	AllowedRails          []string
	MinSellerReputation   int64
	RequireWalletApproval bool
}

func cloneTerms(t IntentTerms) IntentTerms {
	t.Deliverables = append([]string(nil), t.Deliverables...)
	t.EscrowTerms.ReleaseConditions = append([]string(nil), t.EscrowTerms.ReleaseConditions...)
	t.Metadata = cloneMap(t.Metadata)
	return t
}
func IntentHash(t IntentTerms) (string, error) {
	if err := ValidateIntentTerms(t); err != nil {
		return "", err
	}
	b, err := json.Marshal(cloneTerms(t))
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte(signingDomain+"\x00commit\x00"), b...))
	return hex.EncodeToString(h[:]), nil
}
func ValidateIntentTerms(t IntentTerms) error {
	if len(t.Service) == 0 || len(t.Service) > 128 {
		return errors.New("invalid service")
	}
	if len(t.SLA) > 4096 {
		return errors.New("SLA too large")
	}
	if len(t.Deliverables) > 64 {
		return errors.New("too many deliverables")
	}
	for _, v := range t.Deliverables {
		if len(v) == 0 || len(v) > 4096 {
			return errors.New("invalid deliverable")
		}
	}
	if t.Price.Value <= 0 || t.Price.Currency == "" || len(t.Price.Currency) > 32 || t.Price.Rail == "" || len(t.Price.Rail) > 64 {
		return errors.New("invalid atomic-unit price")
	}
	if t.Buyer == "" || t.Seller == "" || t.Buyer == t.Seller {
		return errors.New("invalid buyer/seller")
	}
	if t.Timestamp.IsZero() {
		return errors.New("timestamp required")
	}
	if len(t.Nonce) < 16 || len(t.Nonce) > 128 {
		return errors.New("invalid nonce")
	}
	if len(t.SettlementChain) == 0 || len(t.SettlementChain) > 128 {
		return errors.New("invalid settlement chain")
	}
	if t.EscrowTerms.Expiration <= 0 || t.EscrowTerms.Expiration > MaxIntentTTL {
		return errors.New("invalid intent TTL")
	}
	if len(t.EscrowTerms.ReleaseConditions) == 0 || len(t.EscrowTerms.ReleaseConditions) > 16 {
		return errors.New("invalid release conditions")
	}
	seen := map[string]bool{}
	for _, c := range t.EscrowTerms.ReleaseConditions {
		if len(c) == 0 || len(c) > 128 || seen[c] {
			return errors.New("empty or duplicate release condition")
		}
		seen[c] = true
	}
	if len(t.Metadata) > 64 {
		return errors.New("too many metadata entries")
	}
	for k, v := range t.Metadata {
		if len(k) == 0 || len(k) > 128 || len(v) > 4096 {
			return errors.New("invalid metadata")
		}
	}
	return nil
}
func signingPreimage(role, hash string) ([]byte, error) {
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("malformed intent hash")
	}
	h := sha256.Sum256(append([]byte(signingDomain+"\x00"+role+"\x00"), b...))
	return h[:], nil
}
func SignIntent(t IntentTerms, buyer, seller Wallet) (SignedIntent, error) {
	if buyer == nil || seller == nil {
		return SignedIntent{}, errors.New("wallet required")
	}
	t = cloneTerms(t)
	if buyer.Address() != t.Buyer || seller.Address() != t.Seller {
		return SignedIntent{}, ErrSellerMismatch
	}
	h, err := IntentHash(t)
	if err != nil {
		return SignedIntent{}, err
	}
	bp, _ := signingPreimage("buyer-intent", h)
	sp, _ := signingPreimage("seller-intent", h)
	bs, err := buyer.Sign(bp)
	if err != nil {
		return SignedIntent{}, err
	}
	ss, err := seller.Sign(sp)
	if err != nil {
		return SignedIntent{}, err
	}
	return SignedIntent{t, h, append([]byte(nil), bs...), append([]byte(nil), ss...)}, nil
}
func VerifySignedIntent(i SignedIntent, w Wallet) error {
	if w == nil {
		return errors.New("wallet required")
	}
	h, err := IntentHash(i.Terms)
	if err != nil {
		return err
	}
	if h != i.Hash {
		return errors.New("intent hash mismatch")
	}
	bp, err := signingPreimage("buyer-intent", h)
	if err != nil {
		return err
	}
	sp, _ := signingPreimage("seller-intent", h)
	if !w.Verify(i.Terms.Buyer, bp, i.BuyerSignature) {
		return errors.New("invalid buyer signature")
	}
	if !w.Verify(i.Terms.Seller, sp, i.SellerSignature) {
		return errors.New("invalid seller signature")
	}
	return nil
}
func EvaluatePolicy(p Policy, s AgentProfile, t IntentTerms) error {
	if err := ValidateIntentTerms(t); err != nil {
		return err
	}
	if p.MaxSpend > 0 && t.Price.Value > p.MaxSpend {
		return fmt.Errorf("%w: price exceeds max spend", ErrPolicyDenied)
	}
	if len(p.AllowedCurrencies) > 0 && !contains(p.AllowedCurrencies, t.Price.Currency) {
		return fmt.Errorf("%w: currency", ErrPolicyDenied)
	}
	if len(p.AllowedRails) > 0 && !contains(p.AllowedRails, t.Price.Rail) {
		return fmt.Errorf("%w: rail", ErrPolicyDenied)
	}
	if s.Reputation.Score < p.MinSellerReputation {
		return fmt.Errorf("%w: reputation", ErrPolicyDenied)
	}
	return nil
}

// Ed25519Wallet is a local ACP identity, not an EVM wallet.
type Ed25519Wallet struct {
	address string
	priv    ed25519.PrivateKey
	pubkeys *sync.Map
}

func NewEd25519Wallet(r *sync.Map) (*Ed25519Wallet, error) {
	if r == nil {
		return nil, errors.New("registry required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(pub)
	a := hex.EncodeToString(h[:20])
	r.Store(a, ed25519.PublicKey(append([]byte(nil), pub...)))
	return &Ed25519Wallet{a, priv, r}, nil
}
func (w *Ed25519Wallet) Address() string {
	if w == nil {
		return ""
	}
	return w.address
}
func (w *Ed25519Wallet) Sign(p []byte) ([]byte, error) {
	if w == nil || len(w.priv) != ed25519.PrivateKeySize || len(p) == 0 {
		return nil, errors.New("invalid wallet or payload")
	}
	return ed25519.Sign(w.priv, p), nil
}
func (w *Ed25519Wallet) Verify(a string, p, s []byte) bool {
	if w == nil || len(a) != 40 || len(p) == 0 || len(s) != ed25519.SignatureSize {
		return false
	}
	v, ok := w.pubkeys.Load(a)
	if !ok {
		return false
	}
	pub, ok := v.(ed25519.PublicKey)
	return ok && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, p, s)
}

type SafeWallet struct {
	wallet Wallet
	mu     sync.RWMutex
}

func NewSafeWallet(w Wallet) *SafeWallet { return &SafeWallet{wallet: w} }
func (s *SafeWallet) Address() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.wallet == nil {
		return ""
	}
	return s.wallet.Address()
}
func (s *SafeWallet) Sign(p []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wallet == nil {
		return nil, errors.New("wallet nil")
	}
	return s.wallet.Sign(p)
}
func (s *SafeWallet) Verify(a string, p, b []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.wallet != nil && s.wallet.Verify(a, p, b)
}

type InMemoryDirectory struct {
	mu       sync.RWMutex
	profiles map[string]AgentProfile
}

func NewInMemoryDirectory() *InMemoryDirectory {
	return &InMemoryDirectory{profiles: map[string]AgentProfile{}}
}
func cloneProfile(p AgentProfile) AgentProfile {
	p.Capabilities = append([]string(nil), p.Capabilities...)
	p.Pricing = cloneAmountMap(p.Pricing)
	p.Metadata = cloneMap(p.Metadata)
	return p
}
func (d *InMemoryDirectory) Register(p AgentProfile) error {
	if p.ID == "" || len(p.ID) > 128 || len(p.Capabilities) == 0 || len(p.Capabilities) > 64 || len(p.Pricing) == 0 {
		return errors.New("invalid profile")
	}
	for _, c := range p.Capabilities {
		a, ok := p.Pricing[c]
		if c == "" || !ok || a.Value <= 0 || a.Currency == "" || a.Rail == "" {
			return errors.New("invalid capability pricing")
		}
	}
	if len(p.Metadata) > 64 {
		return errors.New("too much metadata")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.profiles == nil {
		d.profiles = map[string]AgentProfile{}
	}
	d.profiles[p.ID] = cloneProfile(p)
	return nil
}
func (d *InMemoryDirectory) Discover(q ServiceQuery) []AgentProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var o []AgentProfile
	for _, p := range d.profiles {
		a, ok := p.Pricing[q.Capability]
		if !ok || !contains(p.Capabilities, q.Capability) || a.Value <= 0 {
			continue
		}
		if q.MaxPrice.Value > 0 && (a.Value > q.MaxPrice.Value || (q.MaxPrice.Currency != "" && a.Currency != q.MaxPrice.Currency) || (q.MaxPrice.Rail != "" && a.Rail != q.MaxPrice.Rail)) {
			continue
		}
		if q.SettlementRail != "" && a.Rail != q.SettlementRail || p.Reputation.Score < q.MinReputation || !metadataMatches(p.Metadata, q.RequiredMetadata) {
			continue
		}
		o = append(o, cloneProfile(p))
	}
	sort.Slice(o, func(i, j int) bool {
		if o[i].Reputation.Score != o[j].Reputation.Score {
			return o[i].Reputation.Score > o[j].Reputation.Score
		}
		ai, aj := o[i].Pricing[q.Capability].Value, o[j].Pricing[q.Capability].Value
		if ai != aj {
			return ai < aj
		}
		return o[i].ID < o[j].ID
	})
	return o
}

type escrowState string

const (
	stateLocked   escrowState = "locked"
	stateReleased escrowState = "released"
	stateRefunded escrowState = "refunded"
)

type escrowRecord struct {
	receipt  EscrowReceipt
	state    escrowState
	terminal SettlementReceipt
}
type InMemoryEscrow struct {
	mu       sync.Mutex
	byID     map[string]*escrowRecord
	byIntent map[string]string
	now      func() time.Time
}

func NewInMemoryEscrow() *InMemoryEscrow { return NewInMemoryEscrowWithClock(time.Now) }
func NewInMemoryEscrowWithClock(n func() time.Time) *InMemoryEscrow {
	if n == nil {
		n = time.Now
	}
	return &InMemoryEscrow{byID: map[string]*escrowRecord{}, byIntent: map[string]string{}, now: n}
}
func digestID(prefix, hash string) (string, error) {
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != sha256.Size {
		return "", errors.New("malformed intent hash")
	}
	h := sha256.Sum256(append([]byte("CHAINLINK_ACP/"+prefix+"/v1\x00"), b...))
	return prefix + "-" + hex.EncodeToString(h[:]), nil
}
func (e *InMemoryEscrow) Lock(ctx context.Context, i SignedIntent) (EscrowReceipt, error) {
	if e == nil {
		return EscrowReceipt{}, errors.New("nil escrow")
	}
	if e.now == nil {
		e.now = time.Now
	}
	if err := ctx.Err(); err != nil {
		return EscrowReceipt{}, err
	}
	if err := ValidateIntentTerms(i.Terms); err != nil {
		return EscrowReceipt{}, err
	}
	recomputed, err := IntentHash(i.Terms)
	if err != nil {
		return EscrowReceipt{}, err
	}
	if recomputed != i.Hash {
		return EscrowReceipt{}, errors.New("intent hash mismatch")
	}
	if !e.now().UTC().Before(i.Terms.Timestamp.Add(i.Terms.EscrowTerms.Expiration)) {
		return EscrowReceipt{}, ErrIntentExpired
	}
	id, err := digestID("escrow", i.Hash)
	if err != nil {
		return EscrowReceipt{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.byID == nil {
		e.byID = map[string]*escrowRecord{}
	}
	if e.byIntent == nil {
		e.byIntent = map[string]string{}
	}
	if _, ok := e.byIntent[i.Hash]; ok {
		return EscrowReceipt{}, ErrIntentReplay
	}
	r := EscrowReceipt{id, i.Hash, i.Terms.Buyer, i.Terms.Seller, i.Terms.Price, i.Terms.Timestamp.Add(i.Terms.EscrowTerms.Expiration)}
	e.byIntent[i.Hash] = id
	e.byID[id] = &escrowRecord{receipt: r, state: stateLocked}
	return r, nil
}
func (e *InMemoryEscrow) terminal(ctx context.Context, id string, want escrowState) (SettlementReceipt, error) {
	if e == nil {
		return SettlementReceipt{}, errors.New("nil escrow")
	}
	if err := ctx.Err(); err != nil {
		return SettlementReceipt{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.byID[id]
	if !ok {
		return SettlementReceipt{}, errors.New("escrow not found")
	}
	if r.state == want {
		return r.terminal, nil
	}
	if r.state != stateLocked {
		return SettlementReceipt{}, ErrEscrowAlreadySettled
	}
	now := e.now().UTC()
	if want == stateReleased && !now.Before(r.receipt.ExpiresAt) {
		return SettlementReceipt{}, ErrEscrowExpired
	}
	to, status, prefix := r.receipt.Seller, "released", "settlement"
	if want == stateRefunded {
		to, status, prefix = r.receipt.Buyer, "refunded", "refund"
	}
	sid, _ := digestID(prefix, r.receipt.IntentHash)
	r.state = want
	r.terminal = SettlementReceipt{sid, id, to, r.receipt.Amount, r.receipt.Amount.Rail, status, now}
	return r.terminal, nil
}
func (e *InMemoryEscrow) Release(c context.Context, id string) (SettlementReceipt, error) {
	return e.terminal(c, id, stateReleased)
}
func (e *InMemoryEscrow) Refund(c context.Context, id string) (SettlementReceipt, error) {
	return e.terminal(c, id, stateRefunded)
}

type InMemoryReputation struct {
	mu     sync.Mutex
	scores map[string]ReputationScore
	events map[string]string
}

func NewInMemoryReputation() *InMemoryReputation {
	return &InMemoryReputation{scores: map[string]ReputationScore{}, events: map[string]string{}}
}
func (r *InMemoryReputation) Update(ctx context.Context, e ReputationEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.AgentID == "" || (e.IntentHash == "" && e.EventID == "") {
		return errors.New("invalid reputation event")
	}
	if e.EventID == "" {
		e.EventID = e.AgentID + ":" + e.IntentHash + ":" + e.Type + ":" + fmt.Sprint(e.Delta)
	}
	eventBytes, err := json.Marshal(struct {
		AgentID, IntentHash, Type string
		Delta                     int64
		Reason                    string
	}{e.AgentID, e.IntentHash, e.Type, e.Delta, e.Reason})
	if err != nil {
		return err
	}
	eventSum := sha256.Sum256(eventBytes)
	eventDigest := hex.EncodeToString(eventSum[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.events == nil {
		r.events = map[string]string{}
	}
	if r.scores == nil {
		r.scores = map[string]ReputationScore{}
	}
	if old, ok := r.events[e.EventID]; ok {
		if old != eventDigest {
			return ErrIdempotencyConflict
		}
		return nil
	}
	r.events[e.EventID] = eventDigest
	s := r.scores[e.AgentID]
	s.AgentID = e.AgentID
	if e.Delta >= 0 {
		s.Successful += e.Delta
	} else {
		s.Disputed -= e.Delta
	}
	s.Score += e.Delta
	r.scores[e.AgentID] = s
	return nil
}
func (r *InMemoryReputation) Query(ctx context.Context, id string) (ReputationScore, error) {
	if err := ctx.Err(); err != nil {
		return ReputationScore{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scores[id], nil
}

type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	now     func() time.Time
	keys    map[string]string
}

func (l *AuditLog) clock() time.Time {
	if l.now != nil {
		return l.now().UTC()
	}
	return time.Now().UTC()
}
func auditHash(seq uint64, k, r, ph, prev string, t time.Time) string {
	b, _ := json.Marshal(struct {
		Domain                               string
		Sequence                             uint64
		Kind, Ref, PayloadHash, PreviousHash string
		Timestamp                            time.Time
	}{auditDomain, seq, k, r, ph, prev, t})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (l *AuditLog) Store(ctx context.Context, key, k, r string, p any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(key) == "" || strings.TrimSpace(k) == "" || strings.TrimSpace(r) == "" {
		return errors.New("audit key, kind and ref required")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.keys == nil {
		l.keys = make(map[string]string)
	}
	h := sha256.Sum256(b)
	ph := hex.EncodeToString(h[:])
	if existing, ok := l.keys[key]; ok {
		if existing == ph {
			return nil
		}
		return ErrIdempotencyConflict
	}
	seq := uint64(len(l.entries) + 1)
	prev := ""
	if seq > 1 {
		prev = l.entries[seq-2].EntryHash
	}
	t := l.clock()
	l.entries = append(l.entries, AuditEntry{seq, k, r, append([]byte(nil), b...), ph, prev, auditHash(seq, k, r, ph, prev, t), t})
	l.keys[key] = ph
	return nil
}
func (l *AuditLog) Entries() []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	o := make([]AuditEntry, len(l.entries))
	copy(o, l.entries)
	for i := range o {
		o[i].Payload = append([]byte(nil), o[i].Payload...)
	}
	return o
}
func (l *AuditLog) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return ""
	}
	return l.entries[len(l.entries)-1].EntryHash
}
func (l *AuditLog) VerifyIntegrity() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := ""
	for i, e := range l.entries {
		h := sha256.Sum256(e.Payload)
		ph := hex.EncodeToString(h[:])
		if e.Sequence != uint64(i+1) || e.PayloadHash != ph || e.PreviousHash != prev || e.EntryHash != auditHash(e.Sequence, e.Kind, e.Ref, ph, prev, e.Timestamp) {
			return fmt.Errorf("audit integrity failure at sequence %d", e.Sequence)
		}
		prev = e.EntryHash
	}
	return nil
}
func contains(v []string, w string) bool {
	for _, x := range v {
		if x == w {
			return true
		}
	}
	return false
}
func metadataMatches(h, w map[string]string) bool {
	for k, v := range w {
		x, ok := h[k]
		if !ok || x != v {
			return false
		}
	}
	return true
}
func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	o := make(map[string]string, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}
func cloneAmountMap(m map[string]Amount) map[string]Amount {
	if m == nil {
		return nil
	}
	o := make(map[string]Amount, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}
