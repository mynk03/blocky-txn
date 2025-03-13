package state

import (
	log "github.com/sirupsen/logrus"
)

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

	case Leaf:
		// Split node into Branch if keys diverge
		existingKey := node.KeyEnd
		commonPrefix := 0
		for ; commonPrefix < len(existingKey) && commonPrefix < len(key); commonPrefix++ {
			if existingKey[commonPrefix] != key[commonPrefix] {
				break
			}
		}

		// Create a new branch node
		branch := &Node{Type: Branch, Children: make(map[byte]*Node)}

		// Add both leaf nodes to the branch
		branch.Children[existingKey[commonPrefix]] = &Node{Type: Leaf, KeyEnd: existingKey[commonPrefix+1:], Value: node.Value}
		branch.Children[key[commonPrefix]] = &Node{Type: Leaf, KeyEnd: key[commonPrefix+1:], Value: value}
		branch.Hash = t.HashNode(branch)

		if commonPrefix > 0 {
			// Create extension node for common prefix
			ext := &Node{
				Type:   Extension,
				KeyEnd: existingKey[:commonPrefix],
				Children: map[byte]*Node{
					0: branch,
				},
			}
			ext.Hash = t.HashNode(ext)
			*node = *ext
		} else {
			*node = *branch
		}

	case Extension:
		// Split extension node if keys diverge
		existingKey := node.KeyEnd
		commonPrefix := 0
		for ; commonPrefix < len(existingKey) && commonPrefix < len(key); commonPrefix++ {
			if existingKey[commonPrefix] != key[commonPrefix] {
				break
			}
		}

		if commonPrefix == 0 {
			// No common prefix, create new branch node
			branch := &Node{Type: Branch, Children: make(map[byte]*Node)}
			branch.Children[existingKey[0]] = &Node{Type: Leaf, KeyEnd: existingKey[1:], Value: node.Value}
			branch.Children[key[0]] = &Node{Type: Leaf, KeyEnd: key[1:], Value: value}
			branch.Hash = t.HashNode(branch)
			*node = *branch
		} else {
			// Create new extension node for common prefix
			branch := &Node{Type: Branch, Children: make(map[byte]*Node)}
			branch.Children[existingKey[commonPrefix]] = &Node{Type: Leaf, KeyEnd: existingKey[commonPrefix+1:], Value: node.Value}
			branch.Children[key[commonPrefix]] = &Node{Type: Leaf, KeyEnd: key[commonPrefix+1:], Value: value}
			branch.Hash = t.HashNode(branch)

			ext := &Node{
				Type:   Extension,
				KeyEnd: existingKey[:commonPrefix],
				Children: map[byte]*Node{
					0: branch,
				},
			}
			ext.Hash = t.HashNode(ext)
			*node = *ext
		}
	}
}

func (t *Trie) get(node *Node, key []byte) []byte {
	if node == nil {
		log.WithField("key", key).Error("Node is nil for key")
		return nil
	}

	switch node.Type {
	case Branch:
		if len(key) == 0 {
			log.WithField("value", node.Value).Debug("Found value in branch node")
			return node.Value
		}
		nibble := key[0]
		log.WithField("nibble", nibble).Debug("Traversing branch node")
		return t.get(node.Children[nibble], key[1:])
	case Leaf:
		if len(key) < len(node.KeyEnd) || !isEqual(key[:len(node.KeyEnd)], node.KeyEnd) {
			log.WithFields(log.Fields{
				"key":    key,
				"keyEnd": node.KeyEnd,
			}).Error("Key mismatch")
			return nil
		}
		log.WithField("keyEnd", node.KeyEnd).Debug("Found matching key prefix in leaf")
		return node.Value
	case Extension:
		if len(key) < len(node.KeyEnd) || !isEqual(key[:len(node.KeyEnd)], node.KeyEnd) {
			log.WithFields(log.Fields{
				"key":    key,
				"keyEnd": node.KeyEnd,
			}).Error("Key mismatch")
			return nil
		}
		log.WithField("keyEnd", node.KeyEnd).Debug("Found matching key prefix in extension")
		child := node.Children[0]
		if child == nil {
			log.Error("Extension node has no child")
			return nil
		}
		return t.get(child, key[len(node.KeyEnd):])
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
