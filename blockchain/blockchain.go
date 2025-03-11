package blockchain

import "blockchain-simulator/state"

func NewBlockchain() *Blockchain {
	// Create the genesis block
	genesisBlock := CreateGenesisBlock()

	// Initialize the state trie
	stateTrie := state.NewTrie()

	// Seed initial accounts into the state trie
	genesisAccounts := map[string]*state.Account{
		"address1": {Balance: 1000, Nonce: 0},
		"address2": {Balance: 500, Nonce: 0},
	}
	for addr, acc := range genesisAccounts {
		stateTrie.PutAccount(addr, acc)
	}

	// Define validators (for PoS or round-robin)
	validators := []string{"address1", "address2"}

	return &Blockchain{
		Chain:      []Block{genesisBlock},
		StateTrie:  stateTrie,
		PendingTxs: []Transaction{},
		Validators: validators,
	}
}
