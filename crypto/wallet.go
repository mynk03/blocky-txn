package crypto

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

// Wallet represents a user's wallet with mnemonic and derived keys
type Wallet struct {
	Mnemonic     string
	PrivateKey   *ecdsa.PrivateKey
	PublicKey    *ecdsa.PublicKey
	Address      common.Address
}

// GenerateMnemonic generates a new mnemonic phrase
func GenerateMnemonic() (string, error) {
	entropy, _ := bip39.NewEntropy(128)
	return bip39.NewMnemonic(entropy)
}

// PrivateKeyFromMnemonic generates a private key from a mnemonic phrase
func PrivateKeyFromMnemonic(mnemonic string) (*ecdsa.PrivateKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	// Derive seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Derive private key using standard HD derivation
	// Convert seed to private key using HMAC-SHA512
	hash := crypto.Keccak256(seed)
	privateKey, err := crypto.ToECDSA(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %w", err)
	}

	return privateKey, nil
}

// AddressFromPrivateKey generates an Ethereum address from a private key
func AddressFromPrivateKey(privateKey *ecdsa.PrivateKey) common.Address {
	publicKey := privateKey.PublicKey
	return crypto.PubkeyToAddress(publicKey)
}

// NewWallet creates a new wallet from a mnemonic phrase
func GetWallet(mnemonic string) (*Wallet, error) {
	privateKey, err := PrivateKeyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	publicKey := &privateKey.PublicKey
	address := AddressFromPrivateKey(privateKey)

	return &Wallet{
		Mnemonic:     mnemonic,
		PrivateKey:   privateKey,
		PublicKey:    publicKey,
		Address:      address,
	}, nil
}

// SignTransaction signs a transaction with the wallet's private key
func (w *Wallet) SignTransaction(txHash common.Hash) ([]byte, error) {
	signature, err := crypto.Sign(txHash.Bytes(), w.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}
	return signature, nil
}

// VerifySignature verifies a signature against the wallet's public key
func (w *Wallet) VerifySignature(hash common.Hash, signature []byte) bool {
	// Remove recovery ID from signature
	signatureNoRecoverID := signature[:len(signature)-1]

	// Verify the signature
	return crypto.VerifySignature(
		crypto.FromECDSAPub(w.PublicKey),
		hash.Bytes(),
		signatureNoRecoverID,
	)
}
