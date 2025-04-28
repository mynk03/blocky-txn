// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	state "blockchain-simulator/state"
)

// ProcessBlock applies transactions to the state trie.
// ProcessBlock updates the state trie with transactions from a block.
func ProcessBlock(block Block, trie *state.MptTrie) {
	for _, tx := range block.Transactions {
		sender, _ := trie.GetAccount(tx.Sender)

		receiver, _ := trie.GetAccount(tx.Receiver)

		// Update balances and nonce
		sender.Balance -= tx.Amount
		sender.Nonce++
		receiver.Balance += tx.Amount

		// Save to state trie
		trie.PutAccount(tx.Sender, sender)
		trie.PutAccount(tx.Receiver, receiver)
	}
}
