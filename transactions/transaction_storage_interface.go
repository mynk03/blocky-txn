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
