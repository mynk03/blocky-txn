package state

import (
	log "github.com/sirupsen/logrus"
)

func (t *Trie) insert(node *Node, key []byte, value []byte) *Node {
    // Handle insertion into a nil node (empty trie)
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
        // Recursively insert into the child, which may be nil
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

        // Existing Leaf becomes part of the new branch
        if len(existingKey) > commonPrefix {
            branch.Children[existingKey[commonPrefix]] = &Node{
                Type:   Leaf,
                KeyEnd: existingKey[commonPrefix+1:],
                Value:  node.Value,
            }
        } else {
            branch.Value = node.Value // Existing node's value at branch
        }

        // New key part
        if len(key) > commonPrefix {
            branch.Children[key[commonPrefix]] = &Node{
                Type:   Leaf,
                KeyEnd: key[commonPrefix+1:],
                Value:  value,
            }
        } else {
            branch.Value = value // New value at branch
        }

        branch.Hash = t.HashNode(branch)

        if commonPrefix > 0 {
            // Wrap the branch in an Extension node for the common prefix
            ext := &Node{
                Type:    Extension,
                KeyEnd:  existingKey[:commonPrefix],
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
            // Convert extension to a branch
            branch := &Node{Type: Branch, Children: make(map[byte]*Node)}
            // Original extension's child
            if len(existingKey) > 0 {
                branch.Children[existingKey[0]] = &Node{
                    Type:    Extension,
                    KeyEnd:  existingKey[1:],
                    Children: node.Children,
                }
            } else {
                branch.Children[0] = node.Children[0]
            }
            // New key part
            branch.Children[key[0]] = &Node{
                Type:   Leaf,
                KeyEnd: key[1:],
                Value:  value,
            }
            branch.Hash = t.HashNode(branch)
            return branch
        }

        // Split the extension into a new extension and branch
        newExtKey := existingKey[:commonPrefix]
        remainingExistingKey := existingKey[commonPrefix:]
        remainingNewKey := key[commonPrefix:]

        branch := &Node{Type: Branch, Children: make(map[byte]*Node)}
        if len(remainingExistingKey) > 0 {
            branch.Children[remainingExistingKey[0]] = &Node{
                Type:    Extension,
                KeyEnd:  remainingExistingKey[1:],
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

        // Create new extension for the common prefix
        ext := &Node{
            Type:    Extension,
            KeyEnd:  newExtKey,
            Children: map[byte]*Node{0: branch},
        }
        ext.Hash = t.HashNode(ext)
        return ext
    }

    return node
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
		// Check if the leaf's key segment matches the start of key.
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
		// Ensure the key starts with the extension's key segment.
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
