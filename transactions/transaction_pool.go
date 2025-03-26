package transactions

import (
	"errors"

	"golang.org/x/exp/slices"
)

// TransactionPool manages the lifecycle of transactions, including tracking pending and processed transactions.
type TransactionPool struct {
	PendingTransactions []Transaction      // List of transactions that are yet to be confirmed or finalized.
	storage             TransactionStorage // Storage layer responsible for persisting transaction data.
}

// NewTransactionPool initializes a new TransactionPool
func NewTransactionPool(storage TransactionStorage) (*TransactionPool, TransactionStorage) {

	transactionPool := &TransactionPool{
		PendingTransactions: []Transaction{},
		storage:             storage,
	}

	return transactionPool, storage
}

// AddTransaction adds a transaction to the PendingTransactions and AllTransactions
func (tp *TransactionPool) AddTransaction(tx Transaction) error {
	if status, _ := tx.Validate(); !status {
		return errors.New("invalid transaction")
	}
	tp.PendingTransactions = append(tp.PendingTransactions, tx)
	if err := tp.storage.PutTransaction(tx); err != nil {
		return err
	}
	return nil
}

// RemoveTransaction removes a transaction from the PendingTransactions
func (tp *TransactionPool) RemoveTransaction(hash string) error {
	for i, tx := range tp.PendingTransactions {
		if tx.TransactionHash == hash {
			tp.PendingTransactions = slices.Delete(tp.PendingTransactions, i, i+1)
		}
	}
	if err := tp.storage.RemoveTransaction(hash); err != nil {
		return err
	}
	return nil
}

// RemoveBulkTransactions removes multiple transactions from the PendingTransactions
func (tp *TransactionPool) RemoveBulkTransactions(hashes []string) error {
	for _, hash := range hashes {
		if err := tp.RemoveTransaction(hash); err != nil {
			return err
		}
	}
	return nil
}

// GetPendingTransactions returns the PendingTransactions
func (tp *TransactionPool) GetPendingTransactions() []Transaction {
	return tp.PendingTransactions
}

// GetTransactionByHash returns a transaction by hash
func (tp *TransactionPool) GetTransactionByHash(hash string) *Transaction {
	for _, tx := range tp.PendingTransactions {
		if tx.TransactionHash == hash {
			return &tx
		}
	}
	return nil
}

// GetPendingTransactions returns the PendingTransactions From Storage
func (tp *TransactionPool) GetPendingTransactionsFromStorage() ([]Transaction, error) {
	return tp.storage.GetPendingTransactions()
}

// GetTransactionByHashFromStorage returns a transaction by hash from storage
func (tp *TransactionPool) GetTransactionByHashFromStorage(hash string) (*Transaction, error) {
	tx, err := tp.storage.GetTransaction(hash)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}
