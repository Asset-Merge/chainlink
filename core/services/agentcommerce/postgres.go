package agentcommerce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"database/sql"
)

// PostgresRepository is the durable ACP repository. sqlx.DB is the concrete
// database used by Chainlink's sqlutil.DataSource; transaction ownership stays
// here so the two security-critical multi-record writes cannot be split.
type PostgresRepository struct{ db *sql.DB }

func NewPostgresRepository(db *sql.DB) (*PostgresRepository, error) {
	if db == nil {
		return nil, errors.New("nil ACP database")
	}
	return &PostgresRepository{db: db}, nil
}

func (p *PostgresRepository) CommitReplayAndEscrow(ctx context.Context, replay ReplayRecord, escrow EscrowRecord) error {
	if err := validatePreExecutionRecords(replay, escrow); err != nil {
		return err
	}
	intent, err := json.Marshal(escrow.Intent)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_commerce.replays
		(nonce,intent_hash,state,schema_version,version) VALUES ($1,$2,'committed',$3,$4)`, replay.Nonce, replay.IntentHash, replay.SchemaVersion, replay.Version); err != nil {
		return fmt.Errorf("insert replay: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_commerce.escrows
		(escrow_id,intent_hash,nonce,state,signed_intent,schema_version,version) VALUES ($1,$2,$3,'locked',$4,$5,$6)`, escrow.EscrowID, escrow.IntentHash, escrow.Nonce, intent, escrow.SchemaVersion, escrow.Version); err != nil {
		return fmt.Errorf("insert escrow: %w", err)
	}
	return tx.Commit()
}

func validatePreExecutionRecords(r ReplayRecord, e EscrowRecord) error {
	if r.SchemaVersion != persistenceSchemaV1 || e.SchemaVersion != persistenceSchemaV1 || r.Version == 0 || e.Version == 0 || r.Nonce == "" || r.IntentHash == "" || e.EscrowID == "" || e.Nonce != r.Nonce || e.IntentHash != r.IntentHash {
		return errors.New("invalid pre-execution records")
	}
	h, err := IntentHash(e.Intent.Terms)
	if err != nil || h != r.IntentHash || e.Intent.Hash != h {
		return errors.New("escrow intent/hash mismatch")
	}
	return nil
}

func (p *PostgresRepository) CommitSettlementAndFinalization(ctx context.Context, s SettlementRecord, f FinalizationRecord) error {
	if s.SchemaVersion != persistenceSchemaV1 || s.Version == 0 || s.State != SettlementConfirmed || s.IntentHash == "" || s.IdempotencyKey == "" || s.ExternalID == "" || f.IntentHash != s.IntentHash || f.Receipt != s.Receipt {
		return errors.New("invalid post-settlement records")
	}
	if _, err := s.AmountV2.Atomic.BigInt(); err != nil || s.AmountV2.Currency == "" || s.AmountV2.Rail != "evm" {
		return errors.New("invalid persisted uint256 settlement amount")
	}
	receipt, err := json.Marshal(s.Receipt)
	if err != nil {
		return err
	}
	final, err := json.Marshal(f)
	if err != nil {
		return err
	}
	amount, err := json.Marshal(s.AmountV2)
	if err != nil {
		return err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_commerce.settlements (intent_hash,idempotency_key,external_id,state,receipt,amount_v2,schema_version,version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, s.IntentHash, s.IdempotencyKey, s.ExternalID, s.State, receipt, amount, s.SchemaVersion, s.Version); err != nil {
		return fmt.Errorf("insert settlement: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_commerce.finalizations (intent_hash,record,schema_version,version) VALUES ($1,$2,$3,$4)`, f.IntentHash, final, persistenceSchemaV1, uint64(1)); err != nil {
		return fmt.Errorf("insert finalization: %w", err)
	}
	return tx.Commit()
}

func canonicalDigest(v any) ([]byte, string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:]), nil
}

func (p *PostgresRepository) StoreAuditEvent(ctx context.Context, r AuditEventRecord) error {
	if r.SchemaVersion != persistenceSchemaV1 || r.Key == "" || r.Kind == "" || r.Ref == "" {
		return errors.New("invalid audit record")
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO agent_commerce.audit_events (event_key,intent_hash,kind,payload,payload_digest,schema_version) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (event_key) DO NOTHING`, r.Key, r.Ref, r.Kind, r.Payload, r.Digest, r.SchemaVersion)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return nil
	}
	var digest string
	if err = p.db.QueryRowContext(ctx, `SELECT payload_digest FROM agent_commerce.audit_events WHERE event_key=$1`, r.Key).Scan(&digest); err != nil {
		return err
	}
	if digest != r.Digest {
		return ErrIdempotencyConflict
	}
	return nil
}

func (p *PostgresRepository) ApplyReputationEvent(ctx context.Context, r ReputationEventRecord) error {
	if r.SchemaVersion != persistenceSchemaV1 || r.Event.EventID == "" {
		return errors.New("invalid reputation record")
	}
	payload, digest, err := canonicalDigest(r.Event)
	if err != nil {
		return err
	}
	if r.Digest != "" && r.Digest != digest {
		return errors.New("reputation digest mismatch")
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO agent_commerce.reputation_events (event_id,agent_id,intent_hash,payload,payload_digest,schema_version) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (event_id) DO NOTHING`, r.Event.EventID, r.Event.AgentID, r.Event.IntentHash, payload, digest, r.SchemaVersion)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 1 {
		return nil
	}
	var got string
	if err = p.db.QueryRowContext(ctx, `SELECT payload_digest FROM agent_commerce.reputation_events WHERE event_id=$1`, r.Event.EventID).Scan(&got); err != nil {
		return err
	}
	if got != digest {
		return ErrIdempotencyConflict
	}
	return nil
}

func (p *PostgresRepository) GetSettlement(ctx context.Context, key string) (SettlementRecord, error) {
	var r SettlementRecord
	var receipt, amount []byte
	err := p.db.QueryRowContext(ctx, `SELECT intent_hash,idempotency_key,external_id,state,receipt,amount_v2,schema_version,version FROM agent_commerce.settlements WHERE idempotency_key=$1`, key).Scan(&r.IntentHash, &r.IdempotencyKey, &r.ExternalID, &r.State, &receipt, &amount, &r.SchemaVersion, &r.Version)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(receipt, &r.Receipt); err != nil {
		return r, err
	}
	err = json.Unmarshal(amount, &r.AmountV2)
	return r, err
}
