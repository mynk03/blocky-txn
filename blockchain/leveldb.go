package blockchain

import (
	"blockchain-simulator/state"
	"blockchain-simulator/transactions"
	"encoding/json"
	"log"

	"github.com/syndtr/goleveldb/leveldb"
)

// LevelDBStorage implements the Storage interface using LevelDB as the underlying storage engine.
// It provides persistent storage for blocks, state, and transactions.
type LevelDBStorage struct {
	db *leveldb.DB
}

const (
	// Prefixes used for different types of data in the database
	blockPrefix       = "b:"         // Prefix for block data
	statePrefix       = "s:"         // Prefix for state trie data
	accountPrefix     = "a:"         // Prefix for account data
	latestKey         = "latest"     // Key for storing the latest block hash
	transactionPrefix = "tx:"        // Prefix for transaction data
	pendingKey        = "pendingTx:" // Key for storing pending transactions
)

// InitializeStorage creates and initializes a new LevelDB storage instance.
// It uses a default path "./chaindata" for the database files.
// Returns a pointer to the initialized LevelDBStorage.
func InitializeStorage() *LevelDBStorage {
	dbPath := "./chaindata"
	storage, err := NewLevelDBStorage(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	return storage
}

// NewLevelDBStorage creates a new LevelDB storage instance at the specified path.
// It opens the LevelDB database and returns a pointer to the LevelDBStorage struct.
func NewLevelDBStorage(path string) (*LevelDBStorage, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	return &LevelDBStorage{db: db}, nil
}

// PutBlock stores a block in the database.
// It serializes the block to JSON and stores it using the block's hash as the key.
// It also updates the latest block reference.
func (s *LevelDBStorage) PutBlock(block Block) error {
	data, err := json.Marshal(block)
	if err != nil {
		return err
	}

	// Store block
	err = s.db.Put([]byte(blockPrefix+block.Hash), data, nil)
	if err != nil {
		return err
	}

	// Update latest block
	return s.db.Put([]byte(latestKey), []byte(block.Hash), nil)
}

// GetBlock retrieves a block from the database using its hash.
// It deserializes the stored JSON data back into a Block struct.
func (s *LevelDBStorage) GetBlock(hash string) (Block, error) {
	data, err := s.db.Get([]byte(blockPrefix+hash), nil)
	if err != nil {
		return Block{}, err
	}

	var block Block
	err = json.Unmarshal(data, &block)
	return block, err
}

// GetLatestBlock retrieves the most recently added block from the database.
// It first gets the latest block hash, then retrieves the full block data.
func (s *LevelDBStorage) GetLatestBlock() (Block, error) {
	hash, err := s.db.Get([]byte(latestKey), nil)
	if err != nil {
		return Block{}, err
	}
	return s.GetBlock(string(hash))
}

// PutState stores the state trie in the database.
// It serializes the state trie to JSON and stores it using the state root hash as the key.
func (s *LevelDBStorage) PutState(stateRoot string, trie *state.MptTrie) error {
	data, err := json.Marshal(trie)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(statePrefix+stateRoot), data, nil)
}

// GetState retrieves the state trie from the database using its root hash.
// It deserializes the stored JSON data back into an MptTrie struct.
func (s *LevelDBStorage) GetState(stateRoot string) (*state.MptTrie, error) {
	data, err := s.db.Get([]byte(statePrefix+stateRoot), nil)
	if err != nil {
		return nil, err
	}

	var trie state.MptTrie
	err = json.Unmarshal(data, &trie)
	return &trie, err
}

// PutTransaction stores a transaction in the database.
// It serializes the transaction to JSON and stores it using the transaction's hash as the key.
func (s *LevelDBStorage) PutTransaction(tx transactions.Transaction) error {
	data, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(transactionPrefix+tx.GenerateHash()), data, nil)
}

// GetTransaction retrieves a transaction from the database using its hash.
// It deserializes the stored JSON data back into a Transaction struct.
func (s *LevelDBStorage) GetTransaction(hash string) (transactions.Transaction, error) {
	data, err := s.db.Get([]byte(transactionPrefix+hash), nil)
	if err != nil {
		return transactions.Transaction{}, err
	}
	var tx transactions.Transaction
	err = json.Unmarshal(data, &tx)
	return tx, err
}

// GetPendingTransactions retrieves all pending transactions from the database.
// It deserializes the stored JSON data back into a slice of Transaction structs.
func (s *LevelDBStorage) GetPendingTransactions() ([]transactions.Transaction, error) {
	data, err := s.db.Get([]byte(pendingKey), nil)
	if err != nil {
		return nil, err
	}
	var transactions []transactions.Transaction
	err = json.Unmarshal(data, &transactions)
	return transactions, err
}

// RemoveTransaction removes a transaction from the database using its hash.
func (s *LevelDBStorage) RemoveTransaction(hash string) error {
	return s.db.Delete([]byte(transactionPrefix+hash), nil)
}

// RemoveBulkTransactions removes multiple transactions from the database using their hashes.
// It attempts to remove each transaction and returns an error if any removal fails.
func (s *LevelDBStorage) RemoveBulkTransactions(hashes []string) error {
	for _, hash := range hashes {
		err := s.db.Delete([]byte(transactionPrefix+hash), nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database connection
func (s *LevelDBStorage) Close() error {
	return s.db.Close()
}
