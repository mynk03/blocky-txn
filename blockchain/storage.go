package blockchain

import (
	"blockchain-simulator/state"

	"github.com/ethereum/go-ethereum/common"
)

type Storage interface {
	// Block operations
	PutBlock(block Block) error
	GetBlock(hash string) (Block, error)
	GetLatestBlock() (Block, error)

	// State operations
	PutState(stateRoot string, trie *state.Trie) error
	GetState(stateRoot string) (*state.Trie, error)

	// Account operations
	PutAccount(address common.Address, account *state.Account) error
	GetAccount(address common.Address) (*state.Account, error)

	Close() error
}
