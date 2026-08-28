package agentcommerce

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

var sqlDriverSequence atomic.Uint64

type transactionProbe struct {
	mu                        sync.Mutex
	execs, commits, rollbacks int
	failAt                    int
}
type probeDriver struct{ p *transactionProbe }
type probeConn struct{ p *transactionProbe }
type probeTx struct{ p *transactionProbe }

func (d probeDriver) Open(string) (driver.Conn, error) { return &probeConn{d.p}, nil }
func (*probeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("prepare unsupported") }
func (*probeConn) Close() error                        { return nil }
func (c *probeConn) Begin() (driver.Tx, error)         { return &probeTx{c.p}, nil }
func (c *probeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return &probeTx{c.p}, nil
}
func (c *probeConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	c.p.execs++
	if c.p.failAt == c.p.execs {
		return nil, errors.New("injected SQL failure")
	}
	return driver.RowsAffected(1), nil
}
func (t *probeTx) Commit() error   { t.p.mu.Lock(); defer t.p.mu.Unlock(); t.p.commits++; return nil }
func (t *probeTx) Rollback() error { t.p.mu.Lock(); defer t.p.mu.Unlock(); t.p.rollbacks++; return nil }

func probeDB(t *testing.T, p *transactionProbe) *sql.DB {
	t.Helper()
	name := fmt.Sprintf("acp-probe-%d", sqlDriverSequence.Add(1))
	sql.Register(name, probeDriver{p})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func validPersistencePair(t *testing.T) (ReplayRecord, EscrowRecord) {
	t.Helper()
	terms := validTerms()
	h, err := IntentHash(terms)
	if err != nil {
		t.Fatal(err)
	}
	return ReplayRecord{SchemaVersion: 1, Nonce: terms.Nonce, IntentHash: h, Version: 1}, EscrowRecord{SchemaVersion: 1, EscrowID: "escrow", IntentHash: h, Nonce: terms.Nonce, Intent: SignedIntent{Terms: terms, Hash: h}, Version: 1}
}

func TestPostgresPreExecutionTransactionRollsBackAtomically(t *testing.T) {
	r, e := validPersistencePair(t)
	p := &transactionProbe{failAt: 2}
	repo, _ := NewPostgresRepository(probeDB(t, p))
	if err := repo.CommitReplayAndEscrow(context.Background(), r, e); err == nil {
		t.Fatal("expected failure")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.commits != 0 || p.rollbacks != 1 || p.execs != 2 {
		t.Fatalf("probe=%+v", p)
	}
}
func TestPostgresPreExecutionTransactionCommitsAtomically(t *testing.T) {
	r, e := validPersistencePair(t)
	p := new(transactionProbe)
	repo, _ := NewPostgresRepository(probeDB(t, p))
	if err := repo.CommitReplayAndEscrow(context.Background(), r, e); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.commits != 1 || p.execs != 2 {
		t.Fatalf("probe=%+v", p)
	}
}

func TestPostgresPostSettlementTransactionRollsBackAtomically(t *testing.T) {
	amount, _ := ParseAtomicAmount("1")
	receipt := SettlementReceipt{SettlementID: "settlement"}
	s := SettlementRecord{SchemaVersion: 1, Version: 1, IntentHash: "intent", IdempotencyKey: "key", ExternalID: "0xtx", State: SettlementConfirmed, Receipt: receipt, AmountV2: AssetAmountV2{Atomic: amount, Currency: "LINK", Rail: "evm"}}
	f := FinalizationRecord{IntentHash: "intent", Receipt: receipt}
	p := &transactionProbe{failAt: 2}
	repo, _ := NewPostgresRepository(probeDB(t, p))
	if err := repo.CommitSettlementAndFinalization(context.Background(), s, f); err == nil {
		t.Fatal("expected failure")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.commits != 0 || p.rollbacks != 1 || p.execs != 2 {
		t.Fatalf("probe=%+v", p)
	}
}
