package blockchain

import (
	state "blockchain-simulator/state"
	"blockchain-simulator/transactions"

	"github.com/ethereum/go-ethereum/common"
)

// Block represents a block in the blockchain.
type Block struct {
	Index        uint64                     // Block height
	Timestamp    string                     // Time of creation
	Transactions []transactions.Transaction // Transactions in the block
	PrevHash     string                     // Hash of the previous block
	Hash         string                     // Hash of the current block
	StateRoot    string                     // Root hash of the state trie after applying transactions
	Validator    string                     // Address of the validator who created the block (for PoS)
}

// Blockchain represents the entire chain.
type Blockchain struct {
	Chain           []Block          // Array of blocks
	StateTrie       *state.MptTrie   // Merkle Patricia Trie for account states
	Validators      []common.Address // List of validators (for PoS or round-robin)
	Storage         Storage          // Add storage field
	LastBlockNumber uint64           // index of the last block in the chain
}
