// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	"blockchain-simulator/internal/state"

	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
)

func NewBlockchain(
	storage Storage,
	accountsToFund []string,
	amountsToFund []uint64,
	stakeAmountsToFund []uint64,
	thresholdStake uint64,
	stakeAddress common.Address,
) *Blockchain {
	// Initialize the state trie
	stateTrie := state.NewMptTrie()

	// Create the genesis block
	genesisBlock := CreateGenesisBlock(
		accountsToFund,
		amountsToFund,
		stakeAmountsToFund,
		stateTrie,
	)

	// Store genesis block
	storage.PutBlock(genesisBlock)
	storage.PutState(genesisBlock.StateRoot, stateTrie)

	// Define validators
	var validators []common.Address

	for _, addr := range accountsToFund {
		account, _ := stateTrie.GetAccount(common.HexToAddress(addr))
		if account.Stake >= thresholdStake {
			validators = append(validators, common.HexToAddress(addr))
		}
	}

	return &Blockchain{
		Chain:           []Block{genesisBlock},
		StateTrie:       stateTrie,
		Validators:      validators,
		Storage:         storage,
		ThresholdStake:  thresholdStake,
		LastBlockNumber: genesisBlock.Index,
	}
}

// AddBlock adds a validated block to the chain and updates the state.
func (bc *Blockchain) AddBlock(newBlock Block) (bool, error) {

	// update the index of the block correctly
	newBlock.Index = bc.LastBlockNumber + 1

	// Store block and updated state
	if err := bc.Storage.PutBlock(newBlock); err != nil {
		return false, err
	}

	if err := bc.Storage.PutState(newBlock.StateRoot, bc.StateTrie); err != nil {
		return false, err
	}

	// Update the chain
	bc.Chain = append(bc.Chain, newBlock)
	bc.LastBlockNumber = newBlock.Index
	return true, nil
}

func (bc *Blockchain) GetLatestBlock() Block {
	return bc.Chain[bc.LastBlockNumber]
}

func (bc *Blockchain) GetLatestBlockHash() string {
	if len(bc.Chain) == 0 {
		return ""
	}
	return bc.Chain[bc.LastBlockNumber].Hash
}

func (bc *Blockchain) GetBlockByHash(hash string) Block {
	for _, block := range bc.Chain {
		if block.Hash == hash {
			return block
		}
	}
	log.WithFields(log.Fields{
		"type": "block_not_found",
		"hash": hash,
	}).Error("Block not found")
	return Block{}
}

func (bc *Blockchain) GetBlockByIndex(index int) Block {
	for i, block := range bc.Chain {
		if i == index {
			return block
		}
	}
	log.WithFields(log.Fields{
		"type":         "block_not_found",
		"block_number": index,
	}).Error("Block not found")
	return Block{}
}
