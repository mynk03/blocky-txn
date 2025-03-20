package transactions

import (
	"errors"

	"golang.org/x/exp/slices"
)

type TransactionPool struct {
	PendingTransactions []Transaction
	AllTransactions     []Transaction
	storage             TransactionStorage
}

// NewTransactionPool initializes a new TransactionPool
func NewTransactionPool(storage TransactionStorage) (*TransactionPool, TransactionStorage) {

	transactionPool := &TransactionPool{
		PendingTransactions: []Transaction{},
		AllTransactions:     []Transaction{},
		storage:             storage,
	}

	return transactionPool, storage
}

// AddTransaction adds a transaction to the PendingTransactions and AllTransactions
func (tp *TransactionPool) AddTransaction(tx Transaction) error {
	if !tx.Validate() {
		return errors.New("invalid transaction")
	}
	tp.PendingTransactions = append(tp.PendingTransactions, tx)
	tp.AllTransactions = append(tp.AllTransactions, tx)
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

// GetAllTransactions returns the AllTransactions
func (tp *TransactionPool) GetAllTransactions() []Transaction {
	return tp.AllTransactions
}

// GetPendingTransactions returns the PendingTransactions From Storage
func (tp *TransactionPool) GetPendingTransactionsFromStorage() ([]Transaction, error) {
	return tp.storage.GetPendingTransactions()
}

// GetAllTransactions returns the AllTransactions From Storage
func (tp *TransactionPool) GetAllTransactionsFromStorage() ([]Transaction, error) {
	return tp.storage.GetAllTransactions()
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

// GetTransactionByHashFromStorage returns a transaction by hash from storage
func (tp *TransactionPool) GetTransactionByHashFromStorage(hash string) (*Transaction, error) {
	tx, err := tp.storage.GetTransaction(hash)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}
