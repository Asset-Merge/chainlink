//go:build evm_integration

package agentcommerce

import (
	"context"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/smartcontractkit/chainlink/v2/core/services/keystore"
)

// ManagedEVMAuthorizer signs an already domain-separated 32-byte settlement
// authorization digest with a Chainlink-managed key. No key material leaves the
// keystore. This is an ACP v2 authorization signature, not EIP-712; the current
// keystore Eth interface exposes digest signing rather than a typed-data API.
type ManagedEVMAuthorizer struct {
	keys    keystore.Eth
	chainID *big.Int
	signer  common.Address
}

func NewManagedEVMAuthorizer(keys keystore.Eth, chainID *big.Int, signer string) (*ManagedEVMAuthorizer, error) {
	if keys == nil || chainID == nil || chainID.Sign() <= 0 || !common.IsHexAddress(signer) {
		return nil, errors.New("invalid managed EVM authorizer")
	}
	return &ManagedEVMAuthorizer{keys: keys, chainID: new(big.Int).Set(chainID), signer: common.HexToAddress(signer)}, nil
}
func (a *ManagedEVMAuthorizer) Authorize(ctx context.Context, chainID, domain string, digest []byte) (ChainAuthorization, error) {
	if a == nil || chainID != a.chainID.String() || domain != "CHAINLINK_ACP/settlement-authorization/v2" || len(digest) != crypto.DigestLength {
		return ChainAuthorization{}, errors.New("authorization domain/chain/digest mismatch")
	}
	if err := a.keys.CheckEnabled(ctx, a.signer, a.chainID); err != nil {
		return ChainAuthorization{}, err
	}
	key, err := a.keys.Get(ctx, a.signer.Hex())
	if err != nil {
		return ChainAuthorization{}, err
	}
	sig, err := key.Sign(digest)
	if err != nil {
		return ChainAuthorization{}, err
	}
	return ChainAuthorization{Scheme: "evm-eoa-secp256k1-acp-v2", Signer: a.signer.Hex(), ChainID: a.chainID.String(), Domain: domain, Signature: append([]byte(nil), sig...)}, nil
}
func (a *ManagedEVMAuthorizer) VerifyAuthorization(_ context.Context, auth ChainAuthorization, digest []byte) error {
	if a == nil || auth.Scheme != "evm-eoa-secp256k1-acp-v2" || auth.ChainID != a.chainID.String() || auth.Domain != "CHAINLINK_ACP/settlement-authorization/v2" || !common.IsHexAddress(auth.Signer) || len(digest) != crypto.DigestLength || len(auth.Signature) != crypto.SignatureLength {
		return errors.New("invalid authorization")
	}
	pub, err := crypto.SigToPub(digest, auth.Signature)
	if err != nil {
		return err
	}
	if crypto.PubkeyToAddress(*pub) != common.HexToAddress(auth.Signer) {
		return errors.New("authorization signer mismatch")
	}
	return nil
}
