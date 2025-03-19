package state

import (
	log "github.com/sirupsen/logrus"
)

func (t *Trie) insert(node *Node, key []byte, value []byte) *Node {
	log.WithFields(log.Fields{
		"node":  node,
		"key":   key,
		"value": value,
	}).Debug("Inserting into trie")

	if node == nil {
		newNode := &Node{
			Type:   Leaf,
			KeyEnd: key,
			Value:  value,
		}
		newNode.Hash = t.HashNode(newNode)
		return newNode
	}

	if len(key) == 0 {
		node.Value = value
		node.Hash = t.HashNode(node)
		return node
	}

	switch node.Type {
	case Branch:
		nibble := key[0]
		child := node.Children[nibble]
		node.Children[nibble] = t.insert(child, key[1:], value)
		node.Hash = t.HashNode(node)
		return node

	case Leaf:
		existingKey := node.KeyEnd
		commonPrefix := 0
		for ; commonPrefix < len(existingKey) && commonPrefix < len(key); commonPrefix++ {
			if existingKey[commonPrefix] != key[commonPrefix] {
				break
			}
		}

		branch := &Node{Type: Branch, Children: make(map[byte]*Node)}

		if len(existingKey) > commonPrefix {
			branch.Children[existingKey[commonPrefix]] = &Node{
				Type:   Leaf,
				KeyEnd: existingKey[commonPrefix+1:],
				Value:  node.Value,
			}
		} else {
			branch.Value = node.Value
		}

		if len(key) > commonPrefix {
			branch.Children[key[commonPrefix]] = &Node{
				Type:   Leaf,
				KeyEnd: key[commonPrefix+1:],
				Value:  value,
			}
		} else {
			branch.Value = value
		}

		branch.Hash = t.HashNode(branch)

		if commonPrefix > 0 {
			ext := &Node{
				Type:     Extension,
				KeyEnd:   existingKey[:commonPrefix],
				Children: map[byte]*Node{0: branch},
			}
			ext.Hash = t.HashNode(ext)
			return ext
		}
		return branch

	case Extension:
		existingKey := node.KeyEnd
		commonPrefix := 0
		for ; commonPrefix < len(existingKey) && commonPrefix < len(key); commonPrefix++ {
			if existingKey[commonPrefix] != key[commonPrefix] {
				break
			}
		}

		if commonPrefix == 0 {
			branch := &Node{Type: Branch, Children: make(map[byte]*Node)}
			if len(existingKey) > 0 {
				branch.Children[existingKey[0]] = &Node{
					Type:     Extension,
					KeyEnd:   existingKey[1:],
					Children: node.Children,
				}
			} else {
				branch.Children[0] = node.Children[0]
			}
			branch.Children[key[0]] = &Node{
				Type:   Leaf,
				KeyEnd: key[1:],
				Value:  value,
			}
			branch.Hash = t.HashNode(branch)
			return branch
		}

		newExtKey := existingKey[:commonPrefix]
		remainingExistingKey := existingKey[commonPrefix:]
		remainingNewKey := key[commonPrefix:]

		branch := &Node{Type: Branch, Children: make(map[byte]*Node)}
		if len(remainingExistingKey) > 0 {
			branch.Children[remainingExistingKey[0]] = &Node{
				Type:     Extension,
				KeyEnd:   remainingExistingKey[1:],
				Children: node.Children,
			}
		} else {
			branch.Children[0] = node.Children[0]
		}

		if len(remainingNewKey) > 0 {
			branch.Children[remainingNewKey[0]] = &Node{
				Type:   Leaf,
				KeyEnd: remainingNewKey[1:],
				Value:  value,
			}
		} else {
			branch.Value = value
		}
		branch.Hash = t.HashNode(branch)

		ext := &Node{
			Type:     Extension,
			KeyEnd:   newExtKey,
			Children: map[byte]*Node{0: branch},
		}
		ext.Hash = t.HashNode(ext)
		return ext
	}

	return node
}

func (t *Trie) get(node *Node, key []byte) []byte {
	log.WithFields(log.Fields{
		"node": node,
		"key":  key,
	}).Debug("Retrieving from trie")
	if node == nil {
		log.WithField("key", key).Error("Node is nil for key")
		return nil
	}

	switch node.Type {
	case Branch:
		if len(key) == 0 {
			return node.Value
		}
		nibble := key[0]
		return t.get(node.Children[nibble], key[1:])
	case Leaf:
		if len(key) < len(node.KeyEnd) || !isEqual(key[:len(node.KeyEnd)], node.KeyEnd) {
			return nil
		}
		return node.Value
	case Extension:
		if len(key) < len(node.KeyEnd) || !isEqual(key[:len(node.KeyEnd)], node.KeyEnd) {
			return nil
		}
		child := node.Children[0]
		if child == nil {
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
