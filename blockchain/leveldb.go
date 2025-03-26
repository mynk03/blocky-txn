package blockchain

import (
	"blockchain-simulator/state"
	"encoding/json"
	"log"

	"github.com/syndtr/goleveldb/leveldb"
)

type LevelDBStorage struct {
	db *leveldb.DB
}

const (
	blockPrefix   = "b:" // block prefix
	statePrefix   = "s:" // state prefix
	accountPrefix = "a:" // account prefix
	latestKey     = "latest"
)

// Initialize storage
func InitializeStorage() *LevelDBStorage {
	dbPath := "./chaindata"
	storage, err := NewLevelDBStorage(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	return storage
}

func NewLevelDBStorage(path string) (*LevelDBStorage, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	return &LevelDBStorage{db: db}, nil
}

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

func (s *LevelDBStorage) GetBlock(hash string) (Block, error) {
	data, err := s.db.Get([]byte(blockPrefix+hash), nil)
	if err != nil {
		return Block{}, err
	}

	var block Block
	err = json.Unmarshal(data, &block)
	return block, err
}

func (s *LevelDBStorage) GetLatestBlock() (Block, error) {
	hash, err := s.db.Get([]byte(latestKey), nil)
	if err != nil {
		return Block{}, err
	}
	return s.GetBlock(string(hash))
}

func (s *LevelDBStorage) PutState(stateRoot string, trie *state.MptTrie) error {
	data, err := json.Marshal(trie)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(statePrefix+stateRoot), data, nil)
}

func (s *LevelDBStorage) GetState(stateRoot string) (*state.MptTrie, error) {
	data, err := s.db.Get([]byte(statePrefix+stateRoot), nil)
	if err != nil {
		return nil, err
	}

	var trie state.MptTrie
	err = json.Unmarshal(data, &trie)
	return &trie, err
}

func (s *LevelDBStorage) Close() error {
	return s.db.Close()
}
