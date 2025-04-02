// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	"blockchain-simulator/state"
	"blockchain-simulator/transactions"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// CreateGenesisBlock initializes the first block with prefunded accounts.
func CreateGenesisBlock(accountsToFund []string, amountsToFund []uint64, stateTrie *state.MptTrie) Block {
	// Seed initial accounts into the state trie
	genesisAccounts := map[common.Address]*state.Account{}
	for i, addr := range accountsToFund {
		address := common.HexToAddress(addr)
		account := &state.Account{Balance: amountsToFund[i], Nonce: 0}
		genesisAccounts[address] = account
		stateTrie.PutAccount(address, account)
	}

	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now().UTC().String(),
		Transactions: []transactions.Transaction{},
		PrevHash:     "0",
		Hash:         "", // Populated later
		StateRoot:    stateTrie.RootHash(),
	}

	genesisBlock.Hash = CalculateBlockHash(genesisBlock)
	return genesisBlock
}
