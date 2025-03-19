package blockchain

import (
	"blockchain-simulator/state"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// CreateBlock creates a new block (without mining/PoW for now).
func CreateBlock(transactions []Transaction, prevBlock Block) Block {
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

// ValidateBlock checks block integrity and state root.
func ValidateBlock(newBlock Block, prevBlock Block, trie *state.Trie) bool {

	// Check block linkage
	if newBlock.PrevHash != prevBlock.Hash || newBlock.Index != prevBlock.Index+1 {
		return false
	}

	// Recompute state root after processing transactions
	tempTrie := trie.Copy() // Create a temporary trie for validation
	ProcessBlock(newBlock, tempTrie)
	expectedStateRoot := tempTrie.RootHash()

	newBlock.StateRoot = expectedStateRoot // TODO: remove this line -- validator should set the state root
	return newBlock.StateRoot == expectedStateRoot
}

// AddBlock adds a validated block to the chain and updates the state.
func (bc *Blockchain) AddBlock(newBlock Block) bool {
	prevBlock := bc.Chain[bc.TotalBlocks-1]

	// Validate block linkage and state root
	if !ValidateBlock(newBlock, prevBlock, bc.StateTrie) {
		return false
	}

	// Apply transactions to the state trie
	ProcessBlock(newBlock, bc.StateTrie)

	// Store block and updated state
	if err := bc.Storage.PutBlock(newBlock); err != nil {
		return false
	}

	if err := bc.Storage.PutState(newBlock.StateRoot, bc.StateTrie); err != nil {
		return false
	}
	
	// Update the chain
	bc.Chain = append(bc.Chain, newBlock)
	bc.TotalBlocks++
	return true
}
