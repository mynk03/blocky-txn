package transactions

import (
	"blockchain-simulator/state"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

// TransactionStatus represents the status of a transaction using an enum.
type TransactionStatus int

const (
	Success TransactionStatus = iota
	Pending
	Failed
)

type Transaction struct {
	TransactionHash string            // Hash of the transaction (from, to, amount, nonce), important for removing transactions from the pool
	From            common.Address    // Sender's address
	To              common.Address    // Receiver's address
	BlockNumber     uint32            // Block consisting the transaction
	Timestamp       uint64            // Timestamp of the transaction
	Status          TransactionStatus // Finality status of the Transaction
	Amount          uint64            // Amount to transfer
	Nonce           uint64            // Sender's transaction count
}

// TransactionHash will always uniques as the sender could not have same nonce
func (t *Transaction) GenerateHash() string {
	// Convert values to bytes and concatenate
	data := fmt.Sprintf("%s %s %d %d %d %d %d", t.From, t.To, t.Amount, t.Nonce, t.BlockNumber, t.Timestamp, t.Status)

	// Hash using Keccak256 and return hex string
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func ProcessTransactions(transactions []Transaction, trie *state.MptTrie) {
	for _, tx := range transactions {
		sender, err := trie.GetAccount(tx.From)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"type" : "trie_error",
				"Account": sender,
			}).Error(err)
		}
		receiver, err := trie.GetAccount(tx.To)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"type" : "trie_error",
				"Account": receiver,
			}).Error(err)
		}

		// Validate sender balance and nonce
		if sender.Balance < tx.Amount || sender.Nonce+1 != tx.Nonce {
			// Log the error gracefully (no panic)
			logrus.WithFields(logrus.Fields{
				"type":               "transaction_validation",
				"balance_validation": sender.Balance < tx.Amount,
				"nonce_validation":   sender.Nonce != tx.Nonce,
				"balance":            sender.Balance,
			}).Error("Transaction_validation_failed")
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

// Validate validates the transaction
func (t *Transaction) ValidateWithState(stateTrie *state.MptTrie) (bool, error) {

	if status, err := t.Validate(); !status {
		return false, err
	}

	senderAccount, _ := stateTrie.GetAccount(t.From)
	if senderAccount == nil {
		return false, ErrInvalidSender
	}

	if senderAccount.Balance < t.Amount {
		return false, ErrInsufficientFunds
	}

	if t.Nonce <= 0 && t.Nonce != senderAccount.Nonce {
		return false, ErrInvalidNonce
	}

	if t.BlockNumber <= 0 {
		return false, ErrInvalidBlockNumber
	}
	return true, nil
}

// Validate validates the transaction
func (t *Transaction) Validate() (bool, error) {

	if t.From == (common.Address{}) {
		return false, ErrInvalidSender
	}

	if t.To == (common.Address{}) {
		return false, ErrInvalidRecipient
	}

	if t.Amount <= 0 {
		return false, ErrInvalidAmount
	}

	if t.Nonce <= 0 {
		return false, ErrInvalidNonce
	}

	if t.BlockNumber <= 0 {
		return false, ErrInvalidBlockNumber
	}
	return true, nil
}

var (
	ErrInvalidSender      = errors.New("invalid sender")
	ErrInvalidRecipient   = errors.New("invalid recipient")
	ErrInvalidAmount      = errors.New("invalid amount")
	ErrInvalidNonce       = errors.New("invalid nonce")
	ErrInvalidBlockNumber = errors.New("invalid block number")
	ErrInsufficientFunds  = errors.New("insufficient funds")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrSignatureMismatch  = errors.New("signature doesn't match sender")
)
