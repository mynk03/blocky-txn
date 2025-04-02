// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	"blockchain-simulator/state"

	"github.com/ethereum/go-ethereum/common"
)

func NewBlockchain(storage Storage, accountsToFund []string, amountsToFund []uint64) *Blockchain {
	// Initialize the state trie
	stateTrie := state.NewMptTrie()

	// Create the genesis block
	genesisBlock := CreateGenesisBlock(accountsToFund, amountsToFund, stateTrie)

	// Store genesis block
	storage.PutBlock(genesisBlock)
	storage.PutState(genesisBlock.StateRoot, stateTrie)

	// Define validators (for PoS or round-robin)
	validators := make([]common.Address, len(accountsToFund))
	for i, addr := range accountsToFund {
		validators[i] = common.HexToAddress(addr)
	}

	return &Blockchain{
		Chain:             []Block{genesisBlock},
		StateTrie:         stateTrie,
		Validators:        validators,
		Storage:           storage,
		last_block_number: genesisBlock.Index,
	}
}

func (bc *Blockchain) GetLatestHash() string {
	if len(bc.Chain) == 0 {
		return ""
	}
	return bc.Chain[bc.last_block_number].Hash
}

func (bc *Blockchain) GetBlockByHash(hash string) *Block {
	for _, block := range bc.Chain {
		if block.Hash == hash {
			return &block
		}
	}
	return nil
}
