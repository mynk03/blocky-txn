package blockchain

import (
	"blockchain-simulator/state"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// CreateGenesisBlock initializes the first block with prefunded accounts.
func CreateGenesisBlock(accountsToFund []string, amountsToFund []uint64) Block {
	stateTrie := state.NewTrie()

	// Seed initial accounts into the state trie
	genesisAccounts := map[common.Address]*state.Account{}
	for i, addr := range accountsToFund {
		genesisAccounts[common.HexToAddress(addr)] = &state.Account{Balance: amountsToFund[i], Nonce: 0}
	}

	return Block{
		Index:        0,
		Timestamp:    time.Now().UTC().String(),
		Transactions: []Transaction{},
		PrevHash:     "0",
		Hash:         CalculateBlockHash(Block{Index: 0}), // Placeholder
		StateRoot:    stateTrie.RootHash(),
	}
}

// Create blockchain with storage
func CreateBlockchain(storage *LevelDBStorage, accountsToFund []string, amountsToFund []uint64) *Blockchain {
	// Initialize the state trie
	stateTrie := state.NewTrie()

	// Create the genesis block
	genesisBlock := CreateGenesisBlock(accountsToFund, amountsToFund)

	// Seed initial accounts into the state trie
	genesisAccounts := map[common.Address]*state.Account{}
	for i, addr := range accountsToFund {
		genesisAccounts[common.HexToAddress(addr)] = &state.Account{Balance: amountsToFund[i], Nonce: 0}
	}
	for addr, acc := range genesisAccounts {
		stateTrie.PutAccount(addr, acc)
		storage.PutAccount(addr, acc)
	}

	// Store genesis block
	storage.PutBlock(genesisBlock)
	storage.PutState(genesisBlock.StateRoot, stateTrie)

	return &Blockchain{
		Chain:      []Block{genesisBlock},
		StateTrie:  stateTrie,
		PendingTxs: []Transaction{},
		Validators: []common.Address{},
		storage:    storage,
	}
}
