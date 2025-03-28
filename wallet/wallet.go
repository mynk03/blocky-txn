package wallet

// Package wallet provides mock wallet functionality for testing purposes only.

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// For testing purposes, we can override this function
var generateKey = crypto.GenerateKey

// MockWallet represents a mock wallet for testing purposes
type MockWallet struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
}

// NewMockWallet creates a new mock wallet with a random private key
func NewMockWallet() (*MockWallet, error) {
	// Generate a new private key
	privateKey, err := generateKey()
	if err != nil ||  privateKey == nil {
		return nil, err
	}

	// Generate address from public key
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

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
	if w.privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	return crypto.Sign(hash.Bytes(), w.privateKey)
}
