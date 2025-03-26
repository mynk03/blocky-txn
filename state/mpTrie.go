package state

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/nspcc-dev/neo-go/pkg/core/mpt"
	"github.com/nspcc-dev/neo-go/pkg/core/storage"
)

// MptTrie encapsulates a Merkle Patricia Trie and its underlying storage.
// It uses the mpt package from neo-go to manage state in a trie structure.
type MptTrie struct {
	store storage.Store
	Trie  *mpt.Trie
}

// NewMptTrie creates and initializes a new MptTrie instance.
// It sets up an in-memory store wrapped with a memory cache and initializes
// the trie in ModeAll, which allows all node types.
func NewMptTrie() *MptTrie {
	newStore := storage.NewMemCachedStore(storage.NewMemoryStore())
	return &MptTrie{
		store: newStore,
		Trie:  mpt.NewTrie(nil, mpt.ModeAll, newStore),
	}
}

// PutAccount serializes an Account and stores it in the trie under the key
// derived from the given Ethereum address. The address is converted to nibbles
// to match the trie key format.
func (m *MptTrie) PutAccount(address common.Address, account *Account) error {
	if address == (common.Address{}) {
		return errors.New("address is empty")
	}
	// Convert Ethereum address to a nibble representation for trie indexing.
	addressBytes := addressToNibbles(address)
	// Serialize the Account object into a byte slice.
	accountBytes := account.Serialize()
	// Store the serialized account in the trie.
	err := m.Trie.Put(addressBytes, accountBytes)
	if err != nil {
		return err
	}
	return nil
}

// GetAccount retrieves and deserializes an Account from the trie using the
// provided Ethereum address. The address is converted to nibbles to locate the entry.
func (m *MptTrie) GetAccount(address common.Address) (*Account, error) {
	// Convert Ethereum address to nibble format for querying the trie.
	addressBytes := addressToNibbles(address)
	// Retrieve the stored account bytes from the trie.
	accountBytes, err := m.Trie.Get(addressBytes)
	if err != nil {
		return nil, err
	}
	// Deserialize the account bytes back into an Account object.
	return Deserialize(accountBytes), nil
}

// RootHash returns the string representation of the trie's current state root hash.
// This hash is useful for validating the integrity of the state.
func (t *MptTrie) RootHash() string {
	return t.Trie.StateRoot().String()
}

// Copy creates a copy of the current MptTrie instance.
// Note: This implementation performs a shallow copy of the store and trie reference.
// For full isolation, a deep copy of the underlying trie nodes should be implemented.
func (t *MptTrie) Copy() *MptTrie {
	// Return a new MptTrie instance with the same store and trie.
	return &MptTrie{
		store: t.store,
		Trie:  t.Trie,
	}
}
