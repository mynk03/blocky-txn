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

	genesisAccounts := map[common.Address]*state.Account{}
	for i, addr := range accountsToFund {
		address := common.HexToAddress(addr)
		account := &state.Account{Balance: amountsToFund[i], Nonce: 0}
		genesisAccounts[address] = account
		stateTrie.PutAccount(address, account)
		storage.PutAccount(address, account)
	}

	// Store genesis block
	storage.PutBlock(genesisBlock)
	storage.PutState(genesisBlock.StateRoot, stateTrie)

	// Define validators (for PoS or round-robin)
	validators := make([]common.Address, len(accountsToFund))
	for i, addr := range accountsToFund {
		validators[i] = common.HexToAddress(addr)
	}

	return &Blockchain{
		Chain:      []Block{genesisBlock},
		StateTrie:  stateTrie,
		PendingTxs: []Transaction{},
		Validators: validators,
		storage:    storage,
	}
}

func (bc *Blockchain) GetLatestHash() string {
	if len(bc.Chain) == 0 {
		return ""
	}
	return bc.Chain[len(bc.Chain)-1].Hash
}

func (bc *Blockchain) GetBlockByHash(hash string) *Block {
	for _, block := range bc.Chain {
		if block.Hash == hash {
			return &block
		}
	}
	return nil
}
