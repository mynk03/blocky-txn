// Package wallet provides mock wallet functionality for testing purposes only.
package wallet

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// MockWallet represents a mock wallet for testing purposes
type MockWallet struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
}

// NewMockWallet creates a new mock wallet with a random private key
func NewMockWallet() (*MockWallet, error) {
	// Generate a new private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	// Generate address from public key
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKey)

	return &MockWallet{
		privateKey: privateKey,
		address:    address,
	}, nil
}

// GetAddress returns the wallet's address
func (w *MockWallet) GetAddress() common.Address {
	return w.address
}

// SignTransaction signs a transaction hash with the wallet's private key
func (w *MockWallet) SignTransaction(hash common.Hash) ([]byte, error) {
	return crypto.Sign(hash.Bytes(), w.privateKey)
}
