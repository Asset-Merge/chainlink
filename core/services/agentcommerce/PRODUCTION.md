# ACP production adapter boundary

The ACP orchestrator remains the reference state machine. Its in-memory stores
are useful conformance implementations, but are not a production durability
boundary.

## Existing Chainlink infrastructure to reuse

Production implementations should use, rather than duplicate:

* `github.com/smartcontractkit/chainlink-common/pkg/sqlutil.DataSource` and
  `sqlutil.Transact` for database transactions (an in-repository example is
  `core/bridges/orm.go`).
* Chainlink's `chainlink-evm/pkg/txmgr` dependency for transaction creation,
  state tracking, and receipt lookup. The generated integration mocks at
  `common/txmgr/mocks/evm_tx_store.go` demonstrate its existing
  `FindTxWithIdempotencyKey` and `FindReceiptWithIdempotencyKey` contract.
* `core/services/keystore/eth.go` for managed EVM keys and its chain-ID-bound
  signer. ACP adapter configuration must
  contain key identifiers, never private key material.
* `common/chains` generic chain identifiers and the EVM transaction manager's
  `*big.Int` chain ID at the concrete EVM boundary.

No database schema is selected in this package. The interfaces in
`production.go` deliberately allow the node application to wire these existing
components without making the protocol package depend on PostgreSQL or an RPC
client.

## Required transactions and recovery

The **pre-execution transaction** atomically inserts the escrow record and
commits the replay reservation, with unique constraints on nonce, intent hash,
and escrow ID. A crash before commit leaves neither; a crash after commit leaves
both. Execution must not begin until it commits.

The external settlement provider cannot join the local database transaction.
Every submission therefore uses `SettlementIdempotencyKey`. An ambiguous or
lost response is `pending/unknown`, never a retry signal. Recovery calls
`Lookup` until the adapter reports confirmed success or confirmed failure.

After confirmed success, the **post-settlement transaction** atomically stores
the immutable receipt, external transaction/payment ID, and finalization outbox
record. Uniqueness on intent hash and idempotency key rejects conflicting
receipts. Audit and reputation consumers use unique event keys plus optimistic
record versions, so crashes between the mutation and completion mark replay the
same logical event rather than creating another event.

Crash recovery has the following outcomes:

| Crash point | Recovery rule |
| --- | --- |
| Replay reserved, before pre-execution commit | reservation expires/releases; no escrow exists |
| During atomic replay/escrow commit | transaction exposes both records or neither |
| Execution or verification completed only in memory | rerun only under the executor's own idempotency contract; never infer settlement |
| Before external settlement | lookup deterministic settlement key before submission |
| Submission response lost | lookup; do not resubmit an unknown payment |
| External confirmation before local save | lookup reconstructs the confirmed receipt, then post-settlement transaction saves it |
| Outbox saved before audit/reputation | finalizer resumes incomplete steps |
| Logical event saved before completion mark | same key and payload is idempotent; conflicting payload fails |
| Concurrent/stale finalizer | compare-and-swap rejects stale version; completion flags never move backward |

Persistent adapters should attach leases to replay reservations and finalization
work claims. Lease expiry permits worker recovery, but must not erase committed
replay identities or confirmed settlements.

## Signing and EVM settlement

`ChainAuthorizer` separates ACP's local Ed25519 identity from chain-aware
authorization. An EVM implementation should use EIP-712-style structured data
for an EOA and permit ERC-1271 verification for contract wallets. The chain ID,
settlement domain, token, destination, amount, intent hash, and idempotency key
must be in the authorized commitment.

`EVMSettlementAdapter` is intentionally a narrow skeleton over an injected
transaction submitter. It validates a uint256 amount and chain identity, and
models submitted transfers as pending until receipt lookup reports confirmed or
reverted. It contains no RPC URL, private key, or mainnet behavior.

## Remaining production obligations

Implementations still need database migrations, lease handling, operational
reconciliation workers, confirmation-depth/reorg policy, EVM address/token
validation, gas policy, durable audit anchoring, and process-restart integration
tests against the selected database and transaction manager.

## PostgreSQL implementation and Sepolia gate

`PostgresRepository` uses a real `database/sql` transaction for both critical
boundaries. Migration `0305_agent_commerce_persistence.sql` adds database-level
uniqueness for nonce, intent hash, escrow ID, settlement idempotency key,
external transaction ID, audit event key, and reputation event ID. The node's
standard PostgreSQL driver supplies `*sql.DB`; no connection string is held by
ACP configuration.

The chain-managed signer implementation is compiled with the
`evm_integration` build tag because it imports the node keystore. It calls
`keystore.Eth.CheckEnabled` and `Get`, then signs only the validated ACP v2
settlement digest. The current keystore contract provides digest signing, not a
complete EIP-712 typed-data API; this implementation therefore identifies its
scheme as `evm-eoa-secp256k1-acp-v2` and does **not** claim EIP-712 compatibility.

Sepolia is chain ID `11155111`. Before wiring the adapter into a running node,
an operator can execute the non-broadcast validation gate with a managed signer
address (the address is public, not a secret):

```sh
ACP_SEPOLIA_FROM=0xYOUR_MANAGED_CHAINLINK_KEY_ADDRESS \
  go test ./core/services/agentcommerce -run '^TestSepoliaDryRunGate$' -count=1
```

The test configuration has `Broadcast=false` and rejects attempts to enable it.
Actual broadcast must be initiated through node-owned configuration and the EVM
transaction manager after an operator separately enables the integration. RPC
URLs and keystore passwords remain in the existing Chainlink secrets/config
mechanisms and must never be passed as ACP command-line arguments.

Confirmation is intentionally not inferred from submission. Adapter states are
`submitted`, `pending`, `confirmed`, `reverted`, and `unknown`. Sepolia production wiring must use the node transaction manager's
configured minimum confirmations and finality/reorg tracking before returning
`confirmed`; until then recovery continues lookup by the ACP idempotency key.
