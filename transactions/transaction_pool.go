package transactions

import (
	"errors"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

// TransactionPool manages the lifecycle of transactions, including tracking pending and processed transactions.
type TransactionPool struct {
	PendingTransactions []Transaction // List of transactions that are yet to be confirmed or finalized.
}

// NewTransactionPool initializes a new TransactionPool
func NewTransactionPool() *TransactionPool {

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
	found := false
	for i, tx := range tp.PendingTransactions {
		if tx.TransactionHash == hash {
			tp.PendingTransactions = slices.Delete(tp.PendingTransactions, i, i+1)
			found = true
			break
		}
	}
	if !found {
		return errors.New("transaction hash not found")
	}
	return nil
}

// RemoveBulkTransactions removes multiple transactions from the PendingTransactions
func (tp *TransactionPool) RemoveBulkTransactions(hashes []string) {
	for _, hash := range hashes {
		err := tp.RemoveTransaction(hash)
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
