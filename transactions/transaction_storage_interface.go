// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package transactions

type TransactionStorage interface {
	// Transaction operations
	PutTransaction(tx Transaction) error

	// Getters
	GetTransaction(hash string) (Transaction, error)
	GetPendingTransactions() ([]Transaction, error)
	GetAllTransactions() ([]Transaction, error)

	// Remove
	RemoveTransaction(hash string) error
	RemoveBulkTransactions(hashes []string) error
}
