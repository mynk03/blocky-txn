package state

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
)

// Account represents a user account in the state trie.
type Account struct {
	Balance uint64
	Nonce   uint64
}

// Serialize serializes the account to bytes.
func (a *Account) Serialize() []byte {
	data, err := json.Marshal(a)
	if err != nil {
		log.WithError(err).Error("Error serializing account")
		return nil
	}
	return data
}

// Deserialize deserializes bytes to an account.
func Deserialize(data []byte) *Account {
	var account Account
	err := json.Unmarshal(data, &account)
	if err != nil {
		log.WithError(err).Error("Error deserializing account")
		return nil
	}
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
	if data == nil {
		log.WithField("address", address.Hex()).Error("No data found for address")
		return nil
	}
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
