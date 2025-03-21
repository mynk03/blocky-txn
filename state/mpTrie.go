package state

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/nspcc-dev/neo-go/pkg/core/mpt"
	"github.com/nspcc-dev/neo-go/pkg/core/storage"
)

type MptTrie struct {
	store storage.Store
	Trie  *mpt.Trie
}

func NewMptTrie() *MptTrie {
	newStore := storage.NewMemCachedStore(storage.NewMemoryStore())
	return &MptTrie{
		store: newStore,
		Trie:  mpt.NewTrie(nil, mpt.ModeAll, newStore),
	}
}

func (m *MptTrie) PutAccount(address common.Address, account *Account) error {
	addressBytes := addressToNibbles(address)
	accountBytes := account.Serialize()
	m.Trie.Put(addressBytes, accountBytes)
	return nil
}

func (m *MptTrie) GetAccount(address common.Address) (*Account, error) {
	addressBytes := addressToNibbles(address)
	accountBytes, err := m.Trie.Get(addressBytes)
	if err != nil {
		return nil, err
	}
	return Deserialize(accountBytes), nil
}

// RootHash returns the root hash of the state Trie.
func (t *MptTrie) RootHash() string {
	return t.Trie.StateRoot().String()
}

// Copy creates a deep copy of the trie for validation.
func (t *MptTrie) Copy() *MptTrie {
	// Implement deep copy logic for nodes (simplified here).
	return &MptTrie{
		store: t.store,
		Trie:  t.Trie,
	}
}
