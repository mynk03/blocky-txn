package blockchain

import (
	state "blockchain-simulator/state"

	"github.com/ethereum/go-ethereum/common"
)

// Block represents a block in the blockchain.
type Block struct {
	Index        uint64           // Block height
	Timestamp    string        // Time of creation
	Transactions []Transaction // Transactions in the block
	PrevHash     string        // Hash of the previous block
	Hash         string        // Hash of the current block
	StateRoot    string        // Root hash of the state trie after applying transactions
	Validator    string        // Address of the validator who created the block (for PoS)
}

// Blockchain represents the entire chain.
type Blockchain struct {
	Chain      []Block          // Array of blocks
	StateTrie  *state.Trie      // Merkle Patricia Trie for account states
	PendingTxs []Transaction    // Pending transactions (transaction pool)
	Validators []common.Address // List of validators (for PoS or round-robin)
	Storage    Storage          // Add storage field
	last_block_number uint64    // Last block number
}

// Transaction represents a transaction in the blockchain.
type Transaction struct {
	From   common.Address // Sender's address
	To     common.Address // Receiver's address
	Amount uint64         // Amount to transfer
	Nonce  uint64         // Sender's transaction count
}
