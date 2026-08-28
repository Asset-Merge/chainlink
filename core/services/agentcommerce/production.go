package agentcommerce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	persistenceSchemaV1 = 1
	settlementDomain    = "CHAINLINK_ACP/settlement/v1"
)

var (
	ErrSettlementPending = errors.New("settlement pending or unknown; reconciliation required")
	ErrVersionConflict   = errors.New("optimistic version conflict")
	decimalAmountRE      = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	evmAddressRE         = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	maxUint256           = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
)

// AtomicAmount is a canonical unsigned base-10 number of atomic units. The
// unexported representation prevents construction without uint256 validation.
type AtomicAmount struct{ decimal string }

func ParseAtomicAmount(s string) (AtomicAmount, error) {
	// Bound work before regexp/big.Int parsing hostile input.
	if len(s) == 0 || len(s) > 78 || !decimalAmountRE.MatchString(s) {
		return AtomicAmount{}, errors.New("amount must be canonical unsigned base-10 uint256")
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.Cmp(maxUint256) > 0 {
		return AtomicAmount{}, errors.New("amount exceeds uint256")
	}
	return AtomicAmount{decimal: s}, nil
}

func (a AtomicAmount) String() string { return a.decimal }
func (a AtomicAmount) BigInt() (*big.Int, error) {
	v, err := ParseAtomicAmount(a.decimal)
	if err != nil {
		return nil, err
	}
	n, _ := new(big.Int).SetString(v.decimal, 10)
	return n, nil
}
func (a AtomicAmount) Cmp(b AtomicAmount) (int, error) {
	x, err := a.BigInt()
	if err != nil {
		return 0, err
	}
	y, err := b.BigInt()
	if err != nil {
		return 0, err
	}
	return x.Cmp(y), nil
}
func (a AtomicAmount) MarshalJSON() ([]byte, error) {
	if _, err := a.BigInt(); err != nil {
		return nil, err
	}
	return json.Marshal(a.decimal)
}
func (a *AtomicAmount) UnmarshalJSON(b []byte) error {
	if a == nil {
		return errors.New("nil AtomicAmount")
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("atomic amount must be a JSON string")
	}
	v, err := ParseAtomicAmount(s)
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// AssetAmountV2 preserves asset and rail identity alongside a uint256 amount.
type AssetAmountV2 struct {
	Atomic   AtomicAmount `json:"atomic"`
	Currency string       `json:"currency"`
	Rail     string       `json:"rail"`
}

func (a AssetAmountV2) Compare(b AssetAmountV2) (int, error) {
	if a.Currency == "" || a.Rail == "" || a.Currency != b.Currency || a.Rail != b.Rail {
		return 0, errors.New("asset or settlement rail mismatch")
	}
	return a.Atomic.Cmp(b.Atomic)
}

// Versioned persistence records make schema migrations explicit. Implementors
// must enforce unique nonce, intent hash, escrow ID, event key and settlement key.
type ReplayRecord struct {
	SchemaVersion            int
	Nonce, IntentHash, State string
	Version                  uint64
}
type EscrowRecord struct {
	SchemaVersion                      int
	EscrowID, IntentHash, Nonce, State string
	Intent                             SignedIntent
	Version                            uint64
}
type ReputationEventRecord struct {
	SchemaVersion int
	Event         ReputationEvent
	Digest        string
	Version       uint64
}
type AuditEventRecord struct {
	SchemaVersion  int
	Key, Kind, Ref string
	Payload        []byte
	Digest         string
	Version        uint64
}
type SettlementRecord struct {
	SchemaVersion                          int
	IntentHash, IdempotencyKey, ExternalID string
	Receipt                                SettlementReceipt
	AmountV2                               AssetAmountV2
	State                                  SettlementOutcome
	Version                                uint64
}

// PreExecutionRepository is the required database transaction boundary: replay
// commit and escrow creation succeed or fail together.
type PreExecutionRepository interface {
	CommitReplayAndEscrow(context.Context, ReplayRecord, EscrowRecord) error
}

// PostSettlementRepository atomically persists an immutable confirmed receipt
// and its finalization outbox record.
type PostSettlementRepository interface {
	CommitSettlementAndFinalization(context.Context, SettlementRecord, FinalizationRecord) error
}
type PersistentEscrowRepository interface {
	GetEscrow(context.Context, string) (EscrowRecord, error)
}
type PersistentReputationRepository interface {
	ApplyReputationEvent(context.Context, ReputationEventRecord) error
}
type PersistentAuditRepository interface {
	StoreAuditEvent(context.Context, AuditEventRecord) error
}

type SettlementOutcome string

const (
	SettlementUnknown   SettlementOutcome = "unknown"
	SettlementSubmitted SettlementOutcome = "submitted"
	SettlementPending   SettlementOutcome = "pending"
	SettlementConfirmed SettlementOutcome = "confirmed"
	SettlementReverted  SettlementOutcome = "reverted"
)

type SettlementRequest struct {
	IntentHash, EscrowID, ChainID, Destination, Token string
	Amount                                            AtomicAmount
}

func isEVMAddress(s string) bool { return evmAddressRE.MatchString(s) }

// SignedSettlementTermsV2 closes the legacy int64 boundary: this exact
// canonical object is authorized, persisted, and submitted by production EVM
// adapters. It is intentionally separate from the v1 intent during migration.
type SignedSettlementTermsV2 struct {
	ProtocolVersion string        `json:"protocol_version"`
	IntentHash      string        `json:"intent_hash"`
	EscrowID        string        `json:"escrow_id"`
	ChainID         string        `json:"chain_id"`
	Destination     string        `json:"destination"`
	Token           string        `json:"token"`
	Amount          AssetAmountV2 `json:"amount"`
	IdempotencyKey  string        `json:"idempotency_key"`
}

func SettlementAuthorizationDigest(t SignedSettlementTermsV2) ([]byte, error) {
	if t.ProtocolVersion != "ACP/settlement/v2" || t.Amount.Rail != "evm" {
		return nil, errors.New("invalid settlement authorization version/rail")
	}
	want, err := SettlementIdempotencyKey(t.IntentHash, t.EscrowID)
	if err != nil || want != t.IdempotencyKey {
		return nil, errors.New("settlement idempotency mismatch")
	}
	if !isEVMAddress(t.Destination) || !isEVMAddress(t.Token) {
		return nil, errors.New("invalid EVM address")
	}
	chain, ok := new(big.Int).SetString(t.ChainID, 10)
	if !ok || chain.Sign() <= 0 {
		return nil, errors.New("invalid EVM chain ID")
	}
	if _, err = t.Amount.Atomic.BigInt(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(append([]byte("CHAINLINK_ACP/settlement-authorization/v2\x00"), b...))
	return h[:], nil
}

func (t SignedSettlementTermsV2) Request() (SettlementRequest, error) {
	if _, err := SettlementAuthorizationDigest(t); err != nil {
		return SettlementRequest{}, err
	}
	return SettlementRequest{IntentHash: t.IntentHash, EscrowID: t.EscrowID, ChainID: t.ChainID, Destination: t.Destination, Token: t.Token, Amount: t.Amount.Atomic}, nil
}

type SettlementResult struct {
	Outcome    SettlementOutcome
	ExternalID string
	Receipt    SettlementReceipt
}
type SettlementAdapter interface {
	Settle(context.Context, SettlementRequest, string) (SettlementResult, error)
	Lookup(context.Context, string) (SettlementResult, error)
}

func SettlementIdempotencyKey(intentHash, escrowID string) (string, error) {
	if len(intentHash) != sha256.Size*2 || escrowID == "" {
		return "", errors.New("invalid settlement identity")
	}
	if _, err := hex.DecodeString(intentHash); err != nil {
		return "", errors.New("invalid intent hash")
	}
	h := sha256.Sum256([]byte(settlementDomain + "\x00" + intentHash + "\x00" + escrowID))
	return hex.EncodeToString(h[:]), nil
}

// ReconcileSettlement never resubmits an ambiguous payment. It first looks up
// the deterministic key; only a confirmed failure permits a new Settle call.
func ReconcileSettlement(ctx context.Context, a SettlementAdapter, req SettlementRequest) (SettlementResult, error) {
	key, err := SettlementIdempotencyKey(req.IntentHash, req.EscrowID)
	if err != nil {
		return SettlementResult{}, err
	}
	r, err := a.Lookup(ctx, key)
	if err == nil && r.Outcome == SettlementConfirmed {
		return r, nil
	}
	if err == nil && (r.Outcome == SettlementSubmitted || r.Outcome == SettlementPending || r.Outcome == SettlementUnknown) {
		return r, ErrSettlementPending
	}
	if err != nil {
		return SettlementResult{}, fmt.Errorf("settlement lookup: %w", err)
	}
	if r.Outcome != SettlementReverted {
		return r, ErrSettlementPending
	}
	return a.Settle(ctx, req, key)
}

// ChainAuthorizer is chain/domain-aware without exposing private keys. EOA and
// ERC-1271 implementations can use different schemes behind this boundary.
type ChainAuthorization struct {
	Scheme, Signer, ChainID, Domain string
	Signature                       []byte
}
type ChainAuthorizer interface {
	Authorize(context.Context, string, string, []byte) (ChainAuthorization, error)
	VerifyAuthorization(context.Context, ChainAuthorization, []byte) error
}

// EVMTxSubmitter is the narrow adapter over Chainlink's EVM transaction manager.
// Production wiring should use common/txmgr idempotency and receipt lookup.
type EVMTxSubmitter interface {
	SubmitTokenTransfer(context.Context, string, string, string, *big.Int, string) (string, error)
	LookupTransfer(context.Context, string, string) (SettlementResult, error)
}
type EVMSettlementAdapter struct {
	ChainID   string
	Submitter EVMTxSubmitter
}

func (e EVMSettlementAdapter) Lookup(ctx context.Context, key string) (SettlementResult, error) {
	if e.ChainID == "" || e.Submitter == nil {
		return SettlementResult{}, errors.New("invalid EVM settlement adapter")
	}
	return e.Submitter.LookupTransfer(ctx, e.ChainID, key)
}
func (e EVMSettlementAdapter) Settle(ctx context.Context, r SettlementRequest, key string) (SettlementResult, error) {
	chain, ok := new(big.Int).SetString(e.ChainID, 10)
	if !ok || chain.Sign() <= 0 || r.ChainID != e.ChainID || !isEVMAddress(r.Destination) || !isEVMAddress(r.Token) {
		return SettlementResult{}, errors.New("invalid EVM settlement request")
	}
	n, err := r.Amount.BigInt()
	if err != nil {
		return SettlementResult{}, err
	}
	id, err := e.Submitter.SubmitTokenTransfer(ctx, e.ChainID, r.Destination, r.Token, n, key)
	if err != nil {
		return SettlementResult{Outcome: SettlementUnknown}, err
	}
	return SettlementResult{Outcome: SettlementPending, ExternalID: id}, nil
}

// SepoliaConfig contains identifiers only; URL and credentials remain in the
// node's existing secrets and keystore configuration. Broadcast defaults false.
type SepoliaConfig struct {
	ChainID     string
	FromAddress string
	Broadcast   bool
}

func (c SepoliaConfig) ValidateDryRun() error {
	id, err := strconv.ParseUint(c.ChainID, 10, 64)
	if err != nil || id != 11155111 {
		return errors.New("Sepolia chain ID must be 11155111")
	}
	if !isEVMAddress(c.FromAddress) {
		return errors.New("invalid managed signer address")
	}
	if c.Broadcast {
		return errors.New("broadcast must remain disabled during validation")
	}
	return nil
}

type AuditAnchorRecord struct {
	SchemaVersion      int
	Sequence           uint64
	Head, PreviousHead string
	AnchoredAt         time.Time
	Version            uint64
}
type AuditAnchor interface {
	Anchor(context.Context, AuditAnchorRecord) error
	Latest(context.Context) (AuditAnchorRecord, error)
}
type InMemoryAuditAnchor struct {
	mu     sync.Mutex
	record AuditAnchorRecord
}

func (a *InMemoryAuditAnchor) Anchor(ctx context.Context, r AuditAnchorRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil {
		return errors.New("nil audit anchor")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.SchemaVersion != persistenceSchemaV1 || r.Head == "" || r.Sequence == 0 {
		return errors.New("invalid audit anchor")
	}
	if a.record.Head != "" && (r.Sequence <= a.record.Sequence || r.PreviousHead != a.record.Head) {
		return ErrIdempotencyConflict
	}
	r.Version = a.record.Version + 1
	a.record = r
	return nil
}
func (a *InMemoryAuditAnchor) Latest(ctx context.Context) (AuditAnchorRecord, error) {
	if err := ctx.Err(); err != nil {
		return AuditAnchorRecord{}, err
	}
	if a == nil {
		return AuditAnchorRecord{}, errors.New("nil audit anchor")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.record.Head == "" {
		return AuditAnchorRecord{}, errors.New("audit anchor not found")
	}
	return a.record, nil
}
