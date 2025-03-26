package transactions

import (
	"errors"

	"golang.org/x/exp/slices"
)

// TransactionPool manages the lifecycle of transactions, including tracking pending and processed transactions.
type TransactionPool struct {
	PendingTransactions []Transaction             // List of transactions that are yet to be confirmed or finalized.
}

// NewTransactionPool initializes a new TransactionPool
func NewTransactionPool() (*TransactionPool) {

	transactionPool := &TransactionPool{
		PendingTransactions: []Transaction{},
	}

	return transactionPool
}

// AddTransaction adds a transaction to the PendingTransactions and AllTransactions
func (tp *TransactionPool) AddTransaction(tx Transaction) error {
	if status, _ := tx.Validate(); !status {
		return errors.New("invalid transaction")
	}
	tp.PendingTransactions = append(tp.PendingTransactions, tx)
	return nil
}

// RemoveTransaction removes a transaction from the PendingTransactions
func (tp *TransactionPool) RemoveTransaction(hash string) error {
	for i, tx := range tp.PendingTransactions {
		if tx.TransactionHash == hash {
			tp.PendingTransactions = slices.Delete(tp.PendingTransactions, i, i+1)
		}
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

