package blockchain

import (
	"blockchain-simulator/state"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
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

func (s *LevelDBStorage) PutState(stateRoot string, trie *state.Trie) error {
	data, err := json.Marshal(trie)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(statePrefix+stateRoot), data, nil)
}

func (s *LevelDBStorage) GetState(stateRoot string) (*state.Trie, error) {
	data, err := s.db.Get([]byte(statePrefix+stateRoot), nil)
	if err != nil {
		return nil, err
	}

	var trie state.Trie
	err = json.Unmarshal(data, &trie)
	return &trie, err
}

func (s *LevelDBStorage) PutAccount(address common.Address, account *state.Account) error {
	data, err := json.Marshal(account)
	if err != nil {
		return err
	}
	return s.db.Put([]byte(accountPrefix+address.Hex()), data, nil)
}

func (s *LevelDBStorage) GetAccount(address common.Address) (*state.Account, error) {
	data, err := s.db.Get([]byte(accountPrefix+address.Hex()), nil)
	if err != nil {
		return nil, err
	}

	var account state.Account
	err = json.Unmarshal(data, &account)
	return &account, err
}

func (s *LevelDBStorage) Close() error {
	return s.db.Close()
}
