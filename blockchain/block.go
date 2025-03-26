package blockchain

import (
	"blockchain-simulator/state"
	"blockchain-simulator/transactions"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// CreateBlock creates a new block (without mining/PoW for now).
func CreateBlock(transactions []transactions.Transaction, prevBlock Block) Block {
	newBlock := Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now().UTC().String(),
		Transactions: transactions,
		PrevHash:     prevBlock.Hash,
		Hash:         "", // Populated later
	}

	return newBlock
}

// CalculateBlockHash computes the SHA-256 hash of a block.
func CalculateBlockHash(block Block) string {
	data := fmt.Sprintf("%d %s %v %s", block.Index, block.Timestamp, block.Transactions, block.PrevHash)
	hashBytes := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hashBytes[:])
}

// ? TODO: Should remove this function from here, as it is moved to validator
// ValidateBlock checks block integrity and state root.
func ValidateBlock(newBlock Block, prevBlock Block, trie *state.MptTrie) bool {

	// Check block linkage
	if newBlock.PrevHash != prevBlock.Hash || newBlock.Index != prevBlock.Index+1 {
		return false
	}

	// Recompute state root after processing transactions
	tempTrie := trie.Copy() // Create a temporary trie for validation
	ProcessBlock(newBlock, tempTrie)
	expectedStateRoot := tempTrie.RootHash()

	newBlock.StateRoot = expectedStateRoot
	return newBlock.StateRoot == expectedStateRoot
}

// AddBlock adds a validated block to the chain and updates the state.
func (bc *Blockchain) AddBlock(newBlock Block) (bool, error) {
	// prevBlock := bc.Chain[bc.TotalBlocks-1]


	// ? TODO: could we remove this validation from here, as it is done in the validator?
	// Validate block linkage and state root
	// if !ValidateBlock(newBlock, prevBlock, bc.StateTrie) {
	// 	return false
	// }

	// Apply transactions to the state trie
	if success, err := ProcessBlock(newBlock, bc.StateTrie); !success{
		return false, err
	}

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
