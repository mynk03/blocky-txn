package blockchain

import (
	state "blockchain-simulator/state"
	"fmt"
)

// ProcessBlock applies transactions to the state trie.
// ProcessBlock updates the state trie with transactions from a block.
func ProcessBlock(block Block, trie *state.Trie) {

	fmt.Println("ProcessBlock Here 1", block)
	for _, tx := range block.Transactions {
		sender := trie.GetAccount(tx.From)
		receiver := trie.GetAccount(tx.To)

		fmt.Println("ProcessBlock Here 2", sender, "receiver", receiver)

		// Validate sender balance and nonce
		if sender.Balance < tx.Amount || sender.Nonce != tx.Nonce {
			fmt.Println("ProcessBlock Here 3", sender.Balance, tx.Amount, sender.Nonce, tx.Nonce)
			continue // Skip invalid transactions
		}

		// Update balances and nonce
		sender.Balance -= tx.Amount
		sender.Nonce++
		receiver.Balance += tx.Amount

		fmt.Println("ProcessBlock Here 4", sender , "receiver", receiver)

		// Save to state trie
		trie.PutAccount(tx.From, sender)
		trie.PutAccount(tx.To, receiver)

		fmt.Println("ProcessBlock Here 5", trie)
	}
}
