// Package wallet provides mock implementations for testing purposes only.
// In production, external wallets should be used for actual cryptographic operations.
package wallet

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

// Wallet interface defines the methods that any wallet implementation must provide
type Wallet interface {
	// SignTransaction signs a transaction hash and returns the signature
	SignTransaction(hash common.Hash) ([]byte, error)
	// VerifySignature verifies if a signature is valid for a given hash
	VerifySignature(hash common.Hash, signature []byte) bool
	// GetAddress returns the wallet's address
	GetAddress() common.Address
}

// Wallet represents a user's wallet with mnemonic and derived keys
type WalletStruct struct {
	Mnemonic   string
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	Address    common.Address
}

// MockWallet represents a mock wallet for testing purposes
type MockWallet struct {
	address    common.Address
	privateKey *ecdsa.PrivateKey
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
func GetWallet(mnemonic string) (*WalletStruct, error) {
	privateKey, err := PrivateKeyFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	publicKey := &privateKey.PublicKey
	address := AddressFromPrivateKey(privateKey)

	return &WalletStruct{
		Mnemonic:   mnemonic,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
	}, nil
}

// SignTransaction signs a transaction with the wallet's private key
func (w *WalletStruct) SignTransaction(txHash common.Hash) ([]byte, error) {
	signature, err := crypto.Sign(txHash.Bytes(), w.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}
	return signature, nil
}

// VerifySignature verifies a signature against the wallet's public key
func (w *WalletStruct) VerifySignature(hash common.Hash, signature []byte) bool {
	// Remove recovery ID from signature
	signatureNoRecoverID := signature[:len(signature)-1]

	// Verify the signature
	return crypto.VerifySignature(
		crypto.FromECDSAPub(w.PublicKey),
		hash.Bytes(),
		signatureNoRecoverID,
	)
}

// GetAddress returns the wallet's address
func (w *WalletStruct) GetAddress() common.Address {
	return w.Address
}

// NewMockWallet creates a new mock wallet with a random private key
func NewMockWallet() (Wallet, error) {
	// Generate a random private key for testing
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate mock private key: %w", err)
	}

	// Derive public key and address
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to get public key")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	return &MockWallet{
		address:    address,
		privateKey: privateKey,
	}, nil
}

// NewMockWalletWithAddress creates a new mock wallet with a specific address (for testing specific scenarios)
func NewMockWalletWithAddress(addr common.Address) (Wallet, error) {
	// Generate a random private key for testing
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate mock private key: %w", err)
	}

	return &MockWallet{
		address:    addr,
		privateKey: privateKey,
	}, nil
}

// GetAddress returns the wallet's address
func (w *MockWallet) GetAddress() common.Address {
	return w.address
}

// SignTransaction signs a transaction hash with the mock wallet's private key
// This is only for testing purposes and should not be used in production
func (w *MockWallet) SignTransaction(hash common.Hash) ([]byte, error) {
	// Sign the hash with the private key
	signature, err := crypto.Sign(hash.Bytes(), w.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	return signature, nil
}

// VerifySignature verifies if a signature is valid for a given hash
// This is only for testing purposes and should not be used in production
func (w *MockWallet) VerifySignature(hash common.Hash, signature []byte) bool {
	// Remove recovery ID from signature
	signatureNoRecoverID := signature[:len(signature)-1]

	// Verify the signature
	return crypto.VerifySignature(
		crypto.FromECDSAPub(&w.privateKey.PublicKey),
		hash.Bytes(),
		signatureNoRecoverID,
	)
}
