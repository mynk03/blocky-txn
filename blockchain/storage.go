package blockchain

import (
	"blockchain-simulator/state"
)

type Storage interface {
	// Block operations
	PutBlock(block Block) error
	GetBlock(hash string) (Block, error)
	GetLatestBlock() (Block, error)

	// State operations
	PutState(stateRoot string, trie *state.Trie) error
	GetState(stateRoot string) (*state.Trie, error)
}
