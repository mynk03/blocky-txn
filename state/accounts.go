package state

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
)

// Account represents a user account in the state trie.
type Account struct {
	Address common.Address // Use common.Address for the address
	Balance int
	Nonce   int
}

// Serialize serializes the account to bytes.
func (a *Account) Serialize() []byte {
	data, _ := json.Marshal(a)
	return data
}

// Deserialize deserializes bytes to an account.
func Deserialize(data []byte) *Account {
	var account Account
	json.Unmarshal(data, &account)
	return &account
}

// PutAccount inserts/updates an account in the trie.
func (t *Trie) PutAccount(address common.Address, account *Account) {
	key := addressToNibbles(address) // Convert address to nibbles
	t.insert(t.Root, key, account.Serialize())
}

// GetAccount retrieves an account from the trie.
func (t *Trie) GetAccount(address common.Address) *Account {
	key := addressToNibbles(address)
	data := t.get(t.Root, key)
	return Deserialize(data)
}

// Helper: Convert common.Address to nibbles (e.g., [20]byte -> [40]byte).
func addressToNibbles(address common.Address) []byte {
	var nibbles []byte
	for _, b := range address {
		nibbles = append(nibbles, b>>4, b&0x0F)
	}
	return nibbles
}