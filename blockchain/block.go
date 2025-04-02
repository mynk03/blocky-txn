// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	"blockchain-simulator/transactions"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// CreateBlock creates a new block (without mining/PoW for now).
func CreateBlock(transactions []transactions.Transaction, prevBlock Block) Block {
	newBlock := Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now().UTC().String(),
		Transactions: transactions,
		PrevHash:     prevBlock.Hash,
		Hash:         "", // Populated later
	}

	return newBlock
}

// CalculateBlockHash computes the SHA-256 hash of a block.
func CalculateBlockHash(block Block) string {
	data := fmt.Sprintf("%d %s %v %s", block.Index, block.Timestamp, block.Transactions, block.PrevHash)
	hashBytes := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hashBytes[:])
}
