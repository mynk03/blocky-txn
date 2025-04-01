// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	state "blockchain-simulator/state"

	log "github.com/sirupsen/logrus"
)

// ProcessBlock applies transactions to the state trie.
// ProcessBlock updates the state trie with transactions from a block.
func ProcessBlock(block Block, trie *state.MptTrie) {

	for _, tx := range block.Transactions {
		sender, err := trie.GetAccount(tx.From)
		if err == nil {
			log.WithError(err).Error("Error in Retreiving account")
		}
		receiver, err := trie.GetAccount(tx.To)
		if err == nil {
			log.WithError(err).Error("Error serializing account")
		}

		// Validate sender balance and nonce
		if sender.Balance < tx.Amount || sender.Nonce != tx.Nonce {
			continue // Skip invalid transactions
		}

		// Update balances and nonce
		sender.Balance -= tx.Amount
		sender.Nonce++
		receiver.Balance += tx.Amount

		// Save to state trie
		trie.PutAccount(tx.From, sender)
		trie.PutAccount(tx.To, receiver)
	}
}
