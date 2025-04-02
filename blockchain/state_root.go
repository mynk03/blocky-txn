// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	state "blockchain-simulator/state"

	"github.com/sirupsen/logrus"
)

// ProcessBlock applies transactions to the state trie.
// ProcessBlock updates the state trie with transactions from a block.
func ProcessBlock(block Block, trie *state.MptTrie) {
	for _, tx := range block.Transactions {
		sender, err := trie.GetAccount(tx.From)
		if err != nil {
			logrus.WithError(err).Error("Error in Retreiving sender account")
			continue // Skip this transaction if sender account doesn't exist
		}
		receiver, err := trie.GetAccount(tx.To)
		if err != nil {
			logrus.WithError(err).Error("Error in Retreiving receiver account")
			continue // Skip this transaction if receiver account doesn't exist
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
