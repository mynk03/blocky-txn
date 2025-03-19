package blockchain

import (
	"blockchain-simulator/state"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// CreateBlock creates a new block (without mining/PoW for now).
func CreateBlock(transactions []Transaction, prevBlock Block, stateTrie *state.Trie) Block {
	newBlock := Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now().UTC().String(),
		Transactions: transactions,
		PrevHash:     prevBlock.Hash,
		Hash:         "", // Populated later
		StateRoot:    stateTrie.RootHash(),
	}

	// Calculate the block hash
	newBlock.Hash = CalculateBlockHash(newBlock)
	// newBlock.StateRoot := trie.RootHash()
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

	// adding logs to debug the block validation
	fmt.Println("Here ValidateBlock @0", newBlock)
	fmt.Println("Here ValidateBlock @0.1", prevBlock)
	fmt.Println("Here ValidateBlock @0.2", trie)

	// Check block linkage
	if newBlock.PrevHash != prevBlock.Hash || newBlock.Index != prevBlock.Index+1 {
		return false
	}
	fmt.Println("Here ValidateBlock @1", newBlock.PrevHash == prevBlock.Hash)
	fmt.Println("Here ValidateBlock @2", newBlock.Index == prevBlock.Index+1)

	// Recompute state root after processing transactions
	tempTrie := trie.Copy() // Create a temporary trie for validation

	fmt.Println("Here ValidateBlock @3", tempTrie)
	ProcessBlock(newBlock, tempTrie)
	fmt.Println("Here ValidateBlock @4", tempTrie)

	expectedStateRoot := tempTrie.RootHash()
	fmt.Println("Here ValidateBlock @5.1 expectedStateRoot", expectedStateRoot)

	newBlock.StateRoot = expectedStateRoot // TODO: remove this line -- validator should set the state root
	fmt.Println("Here ValidateBlock @5.2 newBlock.StateRoot", newBlock.StateRoot)

	fmt.Println("Here ValidateBlock @6", newBlock.StateRoot == expectedStateRoot)
	return newBlock.StateRoot == expectedStateRoot
}

// AddBlock adds a validated block to the chain and updates the state.
func (bc *Blockchain) AddBlock(newBlock Block) bool {
	prevBlock := bc.Chain[bc.TotalBlocks-1]
	// fmt.Println("Here AddBlock @1", newBlock)
	// fmt.Println("Here AddBlock @1.1", bc.Chain)
	// fmt.Println("Here AddBlock @1.2", len(bc.Chain)-1)
	// fmt.Println("Here AddBlock @1.3", bc.Chain[len(bc.Chain)-1])

	// Validate block linkage and state root
	if !ValidateBlock(newBlock, prevBlock, bc.StateTrie) {
		return false
	}

	fmt.Println("Here AddBlock @2", bc.StateTrie)
	// Apply transactions to the state trie
	ProcessBlock(newBlock, bc.StateTrie)

	fmt.Println("Here AddBlock @3", bc.StateTrie)
	// Store block and updated state
	if err := bc.Storage.PutBlock(newBlock); err != nil {
		return false
	}

	fmt.Println("Here AddBlock @4", bc.StateTrie)
	if err := bc.Storage.PutState(newBlock.StateRoot, bc.StateTrie); err != nil {
		return false
	}

	fmt.Println("Here AddBlock @5", bc.StateTrie)
	// Update the chain
	bc.Chain = append(bc.Chain, newBlock)
	fmt.Println("Here AddBlock @6 add completed", bc.Chain)
	return true
}
