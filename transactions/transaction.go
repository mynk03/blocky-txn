package transactions

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

type Transaction struct {
	TransactionHash string         // Hash of the transaction (from, to, amount, nonce), important for removing transactions from the pool
	From            common.Address // Sender's address
	To              common.Address // Receiver's address
	Amount          uint64         // Amount to transfer
	Nonce           uint64         // Sender's transaction count
}

// TransactionHash will always uniques as the sender could not have same nonce

func (t *Transaction) Hash() string {
	// Convert values to bytes and concatenate
	data := fmt.Sprintf("%s %s %d %d", t.From, t.To, t.Amount, t.Nonce)

	// Hash using Keccak256 and return hex string
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Validate validates the transaction
func (t *Transaction) Validate() bool {
	return t.From != common.Address{} && t.To != common.Address{} && t.Amount > 0 && t.Nonce > 0
}
