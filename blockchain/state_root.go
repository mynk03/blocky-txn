package blockchain

import (
	state "blockchain-simulator/state"
	"errors"

	"github.com/sirupsen/logrus"
)

// ProcessBlock applies transactions to the state trie.
// ProcessBlock updates the state trie with transactions from a block.
func ProcessBlock(block Block, trie *state.MptTrie) (bool, error) {

	for _, tx := range block.Transactions {
		sender, err := trie.GetAccount(tx.From)
		if err == nil {
			logrus.WithError(err).Error("Error in Retreiving account")
		}
		receiver, err := trie.GetAccount(tx.To)
		if err == nil {
			logrus.WithError(err).Error("Error serializing account")
		}

		// Validate sender balance and nonce
		if sender.Balance < tx.Amount || sender.Nonce != tx.Nonce {
			// Log the error gracefully (no panic)
			logrus.WithFields(logrus.Fields{
				"type":               "transaction_validation",
				"balance_validation": sender.Balance < tx.Amount,
				"nonce_validation":   sender.Nonce != tx.Nonce,
			}).Error("Transaction_validation_failed")
			return false, errors.New("transaction_validation_failed")
		}

		// Update balances and nonce
		sender.Balance -= tx.Amount
		sender.Nonce++
		receiver.Balance += tx.Amount

		// Save to state trie
		trie.PutAccount(tx.From, sender)
		trie.PutAccount(tx.To, receiver)
	}
	return true, nil
}
