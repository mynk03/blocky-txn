package state

import (
	"crypto/sha256"
	"encoding/hex"
)

// NodeType represents the type of trie node.
type NodeType int

const (
	Branch NodeType = iota
	Leaf
	Extension
)

// Node represents a trie node.
type Node struct {
	Type     NodeType
	Children map[byte]*Node // For Branch (indexed 0-15)
	KeyEnd   []byte         // For Leaf/Extension
	Value    []byte         // For Leaf/Branch (value at branch[16])
	Hash     string         // Cached hash of the node
}

// Trie represents the Merkle Patricia Trie.
type Trie struct {
	Root *Node
}

// NewTrie initializes an empty MPT.
func NewTrie() *Trie {
	return &Trie{Root: &Node{Type: Branch, Children: make(map[byte]*Node)}}
}

// HashNode computes the hash of a node.
func (t *Trie) HashNode(node *Node) string {
	var data []byte
	switch node.Type {
	case Branch:
		for i := range 16 {
			child := node.Children[byte(i)]
			if child != nil {
				data = append(data, []byte(child.Hash)...)
			}
		}
		data = append(data, node.Value...)
	case Leaf, Extension:
		data = append(data, node.KeyEnd...)
		data = append(data, node.Value...)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// RootHash returns the root hash of the state trie.
func (t *Trie) RootHash() string {
	return t.HashNode(t.Root)
}

// Copy creates a deep copy of the trie for validation.
func (t *Trie) Copy() *Trie {
	// Implement deep copy logic for nodes (simplified here).
	return &Trie{Root: t.Root}
}
