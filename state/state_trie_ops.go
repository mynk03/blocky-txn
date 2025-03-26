package state

import "encoding/hex"

func (t *Trie) insert(node *Node, key []byte, value []byte) {
	if len(key) == 0 {
		// Update value for Leaf/Branch node
		node.Value = value
		node.Hash = t.HashNode(node)
		return
	}

	switch node.Type {
	case Branch:
		// Traverse or create child node
		nibble := key[0]
		child := node.Children[nibble]
		if child == nil {
			child = &Node{Type: Leaf, KeyEnd: key[1:], Value: value}
			node.Children[nibble] = child
		} else {
			t.insert(child, key[1:], value)
		}
		node.Hash = t.HashNode(node)

	case Leaf, Extension:
		// Split node into Extension + Branch if keys diverge
		existingKey := node.KeyEnd
		commonPrefix := 0
		for ; commonPrefix < len(existingKey) && commonPrefix < len(key); commonPrefix++ {
			if existingKey[commonPrefix] != key[commonPrefix] {
				break
			}
		}

		// Create a new branch node
		branch := &Node{Type: Branch, Children: make(map[byte]*Node)}

		// Compute the branch's hash
		branch.Hash = t.HashNode(branch)

		if commonPrefix > 0 {
			// Convert branch.Hash (hex string) to bytes
			hashBytes, err := hex.DecodeString(branch.Hash)
			if err != nil {
				panic("invalid branch hash")
			}

			// Add an extension node for the common prefix
			ext := &Node{
				Type:   Extension,
				KeyEnd: existingKey[:commonPrefix],
				Value:  hashBytes, // Store the hash bytes
			}
			node = ext
		}

		// Update the branch node
		branch.Children[existingKey[commonPrefix]] = &Node{Type: Leaf, KeyEnd: existingKey[commonPrefix+1:], Value: node.Value}
		branch.Children[key[commonPrefix]] = &Node{Type: Leaf, KeyEnd: key[commonPrefix+1:], Value: value}
		node = branch
	}
}

func (t *Trie) get(node *Node, key []byte) []byte {
	if node == nil {
		return nil
	}

	switch node.Type {
	case Branch:
		if len(key) == 0 {
			return node.Value
		}
		nibble := key[0]
		return t.get(node.Children[nibble], key[1:])
	case Leaf, Extension:
		if len(key) < len(node.KeyEnd) || !isEqual(key[:len(node.KeyEnd)], node.KeyEnd) {
			return nil
		}
		return t.get(node.Children[0], key[len(node.KeyEnd):])
	}
	return nil
}

func isEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
