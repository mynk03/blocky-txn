// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

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

// Function to convert Ethereum address to nibbles
func addressToNibbles(address common.Address) []byte {
	var nibbles []byte
	for _, b := range address {
		nibbles = append(nibbles, b>>4)   // Upper nibble
		nibbles = append(nibbles, b&0x0F) // Lower nibble
	}
	return nibbles
}
