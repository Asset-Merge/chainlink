-- +goose Up

CREATE SCHEMA IF NOT EXISTS agent_commerce;

CREATE TABLE agent_commerce.replays (
    nonce TEXT PRIMARY KEY,
    intent_hash TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'committed')),
    schema_version INTEGER NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_commerce.escrows (
    escrow_id TEXT PRIMARY KEY,
    intent_hash TEXT NOT NULL UNIQUE REFERENCES agent_commerce.replays(intent_hash),
    nonce TEXT NOT NULL UNIQUE REFERENCES agent_commerce.replays(nonce),
    state TEXT NOT NULL CHECK (state IN ('locked', 'released', 'refunded')),
    signed_intent JSONB NOT NULL,
    schema_version INTEGER NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_commerce.settlements (
    intent_hash TEXT PRIMARY KEY REFERENCES agent_commerce.escrows(intent_hash),
    idempotency_key TEXT NOT NULL UNIQUE,
    external_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('confirmed', 'reverted')),
    receipt JSONB NOT NULL,
    amount_v2 JSONB NOT NULL,
    schema_version INTEGER NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_commerce.finalizations (
    intent_hash TEXT PRIMARY KEY REFERENCES agent_commerce.settlements(intent_hash),
    record JSONB NOT NULL,
    audit_complete BOOLEAN NOT NULL DEFAULT FALSE,
    reputation_complete BOOLEAN NOT NULL DEFAULT FALSE,
    complete BOOLEAN NOT NULL DEFAULT FALSE,
    schema_version INTEGER NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_commerce.audit_events (
    event_key TEXT PRIMARY KEY,
    intent_hash TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload BYTEA NOT NULL,
    payload_digest TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (intent_hash, kind)
);

CREATE TABLE agent_commerce.reputation_events (
    event_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    payload JSONB NOT NULL,
    payload_digest TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down

DROP SCHEMA IF EXISTS agent_commerce CASCADE;
