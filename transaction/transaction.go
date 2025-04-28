// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package transaction

import (
	"blockchain-simulator/state"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// TransactionStatus represents the status of a transaction using an enum.
type TransactionStatus int

const (
	Success TransactionStatus = iota
	Pending
	Failed
)

type Transaction struct {
	TransactionHash string            // Hash of the transaction (from, to, amount, nonce), important for removing transactions from the pool
	Sender          common.Address    // Sender's address
	Receiver        common.Address    // Receiver's address
	Amount          uint64            // Amount to transfer
	Nonce           uint64            // Sender's transaction count
	Status          TransactionStatus // Finality status of the Transaction
	BlockNumber     uint32            // Block consisting the transaction
	Timestamp       uint64            // Timestamp of the transaction
	Signature       []byte            // Transaction signature
}

// TransactionHash will always uniques as the sender could not have same nonce
func (t *Transaction) GenerateHash() string {
	// Convert values to bytes and concatenate
	data := fmt.Sprintf("%s %s %d %d %d", t.Sender, t.Receiver, t.Amount, t.Nonce, t.Timestamp)

	// Hash using Keccak256 and return hex string
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Verify verifies the transaction signature
func (t *Transaction) Verify() (bool, error) {
	if t.Signature == nil {
		return false, ErrEmptySignature
	}

	// Generate transaction hash
	txHash := common.HexToHash(t.GenerateHash())

	sigPublicKey, err := ethcrypto.SigToPub(txHash.Bytes(), t.Signature)
	publicKeyBytes := ethcrypto.FromECDSAPub(sigPublicKey)

	if err != nil {
		return false, errors.New(ErrInvalidSignature.Error() + " recovery error: " + err.Error())
	}

	// Convert the recovered public key to an address
	recoveredAddr := common.BytesToAddress(ethcrypto.Keccak256(publicKeyBytes[1:])[12:])

	// Compare the recovered address with the sender's address
	matches := recoveredAddr == t.Sender
	return matches, nil
}

// ValidateWithState validates the transaction with state
func (t *Transaction) ValidateWithState(stateTrie *state.MptTrie) (bool, error) {
	// First check basic validation
	if t.Sender == (common.Address{}) {
		return false, ErrInvalidSender
	}

	if t.Receiver == (common.Address{}) {
		return false, ErrInvalidRecipient
	}

	if t.Amount <= 0 {
		return false, ErrInvalidAmount
	}

	// Check sender account exists and has sufficient funds
	senderAccount, _ := stateTrie.GetAccount(t.Sender)
	if senderAccount == nil {
		return false, ErrInvalidSender
	}

	if senderAccount.Balance < t.Amount {
		return false, ErrInsufficientFunds
	}

	if t.Nonce != senderAccount.Nonce+1 {
		return false, ErrInvalidNonce
	}

	return true, nil
}

var (
	ErrInvalidSender     = errors.New("invalid sender address")
	ErrInvalidRecipient  = errors.New("invalid recipient address")
	ErrInvalidAmount     = errors.New("invalid amount")
	ErrInvalidNonce      = errors.New("invalid nonce")
	ErrInvalidTimestamp  = errors.New("invalid timestamp")
	ErrInsufficientFunds = errors.New("insufficient funds")
	ErrNilStateTrie      = errors.New("state trie is nil")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrSignatureMismatch = errors.New("signature doesn't match sender")
	ErrEmptySignature    = errors.New("signature is empty")
)
