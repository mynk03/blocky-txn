package blockchain

import (
	"blockchain-simulator/state"

	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
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
		Chain:           []Block{genesisBlock},
		StateTrie:       stateTrie,
		Validators:      validators,
		Storage:         storage,
		LastBlockNumber: genesisBlock.Index,
	}
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
