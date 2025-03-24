package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
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

// Validate validates the transaction
func (t *Transaction) Validate() bool {
	return t.isValidAddress() &&
		t.isPositiveAmount() &&
		t.isValidNonce() &&
		t.hasSufficientBalance()
}

func (t *Transaction) isValidAddress() bool {
	return t.From != common.Address{} && t.To != common.Address{}
}

func (t *Transaction) isPositiveAmount() bool {
	return t.Amount > 0
}

func (t *Transaction) isValidNonce() bool {
	return t.Nonce > 0
}

func (t *Transaction) hasSufficientBalance() bool {
	// sender balance ..
	// TODO: need to integrate blockchain's mptTrie storage for sender balance
	balance := uint64(10000)
	return balance >= t.Amount
}
