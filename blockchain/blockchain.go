package blockchain

import (
	"blockchain-simulator/state"

	"github.com/ethereum/go-ethereum/common"
)

func NewBlockchain(storage Storage, accountsToFund []string, amountsToFund []uint64) *Blockchain {
	// Create the genesis block
	genesisBlock := CreateGenesisBlock(accountsToFund, amountsToFund)

	// Initialize the state trie
	stateTrie := state.NewTrie()

	// Seed initial accounts into the state trie
	genesisAccounts := map[common.Address]*state.Account{
		common.HexToAddress("0x0000000000000000000000000000000000000001"): {Balance: 1000, Nonce: 0},
		common.HexToAddress("0x0000000000000000000000000000000000000002"): {Balance: 500, Nonce: 0},
	}
	for addr, acc := range genesisAccounts {
		stateTrie.PutAccount(addr, acc)
	}

	// Store genesis block
	storage.PutBlock(genesisBlock)
	storage.PutState(genesisBlock.StateRoot, stateTrie)

	// Define validators (for PoS or round-robin)
	validators := []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000000001"),
		common.HexToAddress("0x0000000000000000000000000000000000000002"),
	}

	return &Blockchain{
		Chain:      []Block{genesisBlock},
		StateTrie:  stateTrie,
		PendingTxs: []Transaction{},
		Validators: validators,
		storage:    storage,
	}
}
