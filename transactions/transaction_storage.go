package transactions

import (
	"encoding/json"
	"log"

	"github.com/syndtr/goleveldb/leveldb"
)

type LevelDBStorage struct {
	db *leveldb.DB
}

const (
	transactionPrefix = "t:"      // Prefix used for storing transactions in the database, ensuring easy identification and retrieval.
	pendingKey        = "pending" // Key used to store and retrieve all pending transactions.
	allKey            = "all"     // Key used to store and retrieve all transactions, including pending, confirmed, and failed.
)

// Initialize storage
func InitializeStorage(dbPath string) *LevelDBStorage {
	storage, err := newLevelDBStorage(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	return storage
}

// newLevelDBStorage initializes a new LevelDBStorage
func newLevelDBStorage(path string) (*LevelDBStorage, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	return &LevelDBStorage{db: db}, nil
}

// PutTransaction puts a transaction into the database [Transaction Operation]
func (s *LevelDBStorage) PutTransaction(tx Transaction) error {
	data, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(transactionPrefix+tx.GenerateHash()), data, nil)
}

// GetTransaction gets a transaction from the database [Getter]
func (s *LevelDBStorage) GetTransaction(hash string) (Transaction, error) {
	data, err := s.db.Get([]byte(transactionPrefix+hash), nil)
	if err != nil {
		return Transaction{}, err
	}
	var tx Transaction
	err = json.Unmarshal(data, &tx)
	return tx, err
}

// GetPendingTransactions gets all pending transactions from the database [Getter]
func (s *LevelDBStorage) GetPendingTransactions() ([]Transaction, error) {
	data, err := s.db.Get([]byte(pendingKey), nil)
	if err != nil {
		return nil, err
	}
	var transactions []Transaction
	err = json.Unmarshal(data, &transactions)
	return transactions, err
}

// GetAllTransactions gets all transactions from the database [Getter]
func (s *LevelDBStorage) GetAllTransactions() ([]Transaction, error) {
	data, err := s.db.Get([]byte(allKey), nil)
	if err != nil {
		return nil, err
	}
	var transactions []Transaction
	err = json.Unmarshal(data, &transactions)
	return transactions, err
}

// RemoveTransaction removes a transaction from the database [Remover]
func (s *LevelDBStorage) RemoveTransaction(hash string) error {
	return s.db.Delete([]byte(transactionPrefix+hash), nil)
}

// RemoveBulkTransactions removes multiple transactions from the database [Transaction Operation]
func (s *LevelDBStorage) RemoveBulkTransactions(hashes []string) error {
	for _, hash := range hashes {
		err := s.db.Delete([]byte(transactionPrefix+hash), nil)
		if err != nil {
			return err
		}
	}
	return nil
}
