package blockchain

import (
	state "blockchain-simulator/state"
)

// ProcessBlock applies transactions to the state trie.
// ProcessBlock updates the state trie with transactions from a block.
func ProcessBlock(block Block, trie *state.Trie) {
	for _, tx := range block.Transactions {
		sender := trie.GetAccount(tx.From)
		receiver := trie.GetAccount(tx.To)

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
