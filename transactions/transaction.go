// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package transactions

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
	From            common.Address    // Sender's address
	To              common.Address    // Receiver's address
	BlockNumber     uint32            // Block consisting the transaction
	Timestamp       uint64            // Timestamp of the transaction
	Status          TransactionStatus // Finality status of the Transaction
	Amount          uint64            // Amount to transfer
	Nonce           uint64            // Sender's transaction count
	Signature       []byte            // Transaction signature
}

// TransactionHash will always uniques as the sender could not have same nonce
func (t *Transaction) GenerateHash() string {
	// Convert values to bytes and concatenate
	data := fmt.Sprintf("%s %s %d %d %d %d %d", t.From, t.To, t.Amount, t.Nonce, t.BlockNumber, t.Timestamp, t.Status)

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

	sigPublicKey, err := ethcrypto.Ecrecover(txHash.Bytes(), t.Signature)
	if err != nil {
		return false, errors.New(ErrInvalidSignature.Error() + err.Error())
	}

	// Convert the recovered public key to an address
	recoveredAddr := common.BytesToAddress(ethcrypto.Keccak256(sigPublicKey[1:])[12:])

	// Compare the recovered address with the sender's address
	matches := recoveredAddr == t.From
	return matches, nil
}

// ValidateWithState validates the transaction with state
func (t *Transaction) ValidateWithState(stateTrie *state.MptTrie) (bool, error) {
	// First check basic validation
	if status, err := t.Validate(); !status {
		return false, err
	}

	// Check sender account exists and has sufficient funds
	senderAccount, _ := stateTrie.GetAccount(t.From)
	if senderAccount == nil {
		return false, ErrInvalidSender
	}

	if senderAccount.Balance < t.Amount {
		return false, ErrInsufficientFunds
	}

	if t.Nonce != senderAccount.Nonce {
		return false, ErrInvalidNonce
	}

	// Finally verify signature
	matches, err := t.Verify()
	if err != nil {
		return false, err
	}
	if !matches {
		return false, ErrInvalidSignature
	}

	return true, nil
}

// Validate validates the transaction
func (t *Transaction) Validate() (bool, error) {
	if t.From == (common.Address{}) {
		return false, ErrInvalidSender
	}

	if t.To == (common.Address{}) {
		return false, ErrInvalidRecipient
	}

	if t.Amount <= 0 {
		return false, ErrInvalidAmount
	}

	return true, nil
}

var (
	ErrInvalidSender      = errors.New("invalid sender address")
	ErrInvalidRecipient   = errors.New("invalid recipient address")
	ErrInvalidAmount      = errors.New("invalid amount")
	ErrInvalidNonce       = errors.New("invalid nonce")
	ErrInvalidBlockNumber = errors.New("invalid block number")
	ErrInvalidTimestamp   = errors.New("invalid timestamp")
	ErrInsufficientFunds  = errors.New("insufficient funds")
	ErrNilStateTrie       = errors.New("state trie is nil")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrSignatureMismatch  = errors.New("signature doesn't match sender")
	ErrEmptySignature     = errors.New("signature is empty")
)
