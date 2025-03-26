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

		// Skip if either account is nil
		if sender == nil || receiver == nil {
			continue
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
