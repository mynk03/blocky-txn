package transaction

import (
	"errors"
	"sync"

	"github.com/sirupsen/logrus"
)

var (
	ErrDuplicateTransaction = errors.New("transaction already exists in pool")
)

// TransactionPool represents a pool of pending transactions
type TransactionPool struct {
	transactions map[string]Transaction
	mu           sync.RWMutex
}

// NewTransactionPool creates a new transaction pool
func NewTransactionPool() *TransactionPool {
	return &TransactionPool{
		transactions: make(map[string]Transaction),
	}
}

// AddTransaction adds a transaction to the pool
func (pool *TransactionPool) AddTransaction(tx Transaction) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Validate transaction
	if status, err := tx.Validate(); !status {
		return err
	}

	// Check if transaction already exists
	if _, exists := pool.transactions[tx.TransactionHash]; exists {
		return ErrDuplicateTransaction
	}

	pool.transactions[tx.TransactionHash] = tx
	return nil
}

// GetTransaction retrieves a transaction by its hash
func (pool *TransactionPool) GetTransaction(hash string) (Transaction, bool) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	tx, exists := pool.transactions[hash]
	return tx, exists
}

// RemoveTransaction removes a transaction from the pool
func (pool *TransactionPool) RemoveTransaction(hash string) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if _, exists := pool.transactions[hash]; !exists {
		return errors.New("transaction not found")
	}

	delete(pool.transactions, hash)
	return nil
}

// GetAllTransactions returns all transactions in the pool
func (pool *TransactionPool) GetAllTransactions() []Transaction {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	txs := make([]Transaction, 0, len(pool.transactions))
	for _, tx := range pool.transactions {
		txs = append(txs, tx)
	}
	return txs
}

// HasTransaction checks if a transaction exists in the pool
func (pool *TransactionPool) HasTransaction(hash string) bool {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	_, exists := pool.transactions[hash]
	return exists
}

// RemoveBulkTransactions removes multiple transactions from the PendingTransactions
func (pool *TransactionPool) RemoveBulkTransactions(hashes []string) {
	for _, hash := range hashes {
		err := pool.RemoveTransaction(hash)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"type":     "transaction_pool",
				"error":    err,
				"txn_hash": hash,
			}).Error("failed to remove transaction")
		}
	}
}

// GetPendingTransactions returns the PendingTransactions
func (pool *TransactionPool) GetPendingTransactions() []Transaction {
	return pool.GetAllTransactions()
}

// GetTransactionByHash returns a transaction by hash
func (pool *TransactionPool) GetTransactionByHash(hash string) *Transaction {
	tx, exists := pool.GetTransaction(hash)
	if exists {
		return &tx
	}
	return nil
}
