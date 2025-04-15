// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	"blockchain-simulator/state"
	"blockchain-simulator/transaction"

	"github.com/ethereum/go-ethereum/common"
)

// Storage defines the interface for persistent storage operations in the blockchain.
// It provides methods for managing blocks, state, and transactions.
type Storage interface {
	// Block operations
	PutBlock(block Block) error
	GetBlock(hash string) (Block, error)
	GetLatestBlock() (Block, error)

	// State operations
	PutState(stateRoot string, trie *state.MptTrie) error
	GetState(stateRoot string) (*state.MptTrie, error)

	// Transaction operations
	PutTransaction(tx transaction.Transaction) error

	// Transaction Getters
	GetTransaction(hash string) (transaction.Transaction, error)
	GetPendingTransactions() ([]transaction.Transaction, error)
	GetTransactionsBySender(address common.Address) ([]transaction.Transaction, error)

	// Remove Transaction Operations
	RemoveTransaction(hash string) error
	RemoveBulkTransactions(hashes []string) error

	// Close
	Close() error
}
