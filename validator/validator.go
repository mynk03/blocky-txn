package validator

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/transactions"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

// Validator struct to manage transaction validation and block addition
type Validator struct {
	Address         common.Address
	TransactionPool *transactions.TransactionPool
	LocalChain      *blockchain.Blockchain
}

// NewValidator creates a new Validator instance
func NewValidator(address common.Address, tp *transactions.TransactionPool, bc *blockchain.Blockchain) *Validator {
	return &Validator{
		Address:         address,
		TransactionPool: tp,
		LocalChain:      bc,
	}
}

// AddTransaction validates and adds a transaction to the transaction pool
func (v *Validator) AddTransaction(tx transactions.Transaction) error {
	// Validate transaction with current state
	if status, err := tx.ValidateWithState(v.LocalChain.StateTrie); !status {
		logrus.WithFields(logrus.Fields{
			"type":  "transaction_validation",
			"error": err,
		}).Error("Transaction validation failed")
		return err
	}

	// Add validated transaction to pool
	if err := v.TransactionPool.AddTransaction(tx); err != nil {
		logrus.WithFields(logrus.Fields{
			"type":  "transaction_pool",
			"error": err,
		}).Error("Failed to add transaction to pool")
		return err
	}

	return nil
}

// ProposeBlock validates and adds transactions from the transaction pool to the blockchain
func (v *Validator) ProposeNewBlock() blockchain.Block {
	// Get all pending transaction from the transaction pool
	pendingTxs := v.TransactionPool.GetPendingTransactions()
	// Create a new block with the valid transaction
	prevBlock := v.LocalChain.GetLatestBlock()
	newBlock := blockchain.CreateBlock(pendingTxs, prevBlock)

	fmt.Println("here state trie before processing block", v.LocalChain.StateTrie.RootHash())
	// process the transaction on the validator 's state trie
	// transactions.ProcessTransactions(newBlock.Transactions, v.LocalChain.StateTrie)
	blockchain.ProcessBlock(newBlock, v.LocalChain.StateTrie)

	fmt.Println("here state trie after processing block", v.LocalChain.StateTrie.RootHash())
	// update the state root
	newBlock.StateRoot = v.LocalChain.StateTrie.RootHash()
	// return Block
	return newBlock
}

func (v *Validator) ValidateBlock(block blockchain.Block) bool {

	// Check block linkage
	if block.PrevHash == block.Hash || block.Index == v.LocalChain.LastBlockNumber || block.PrevHash == "" {
		return false
	}

	tempStateTrie := v.LocalChain.StateTrie.Copy()

	// process the transaction on the validator's state trie
	blockchain.ProcessBlock(block, tempStateTrie)

	// validate the block state root
	if block.StateRoot != tempStateTrie.RootHash() {
		logrus.WithFields(logrus.Fields{
			"type":  "block_validation",
			"error": "Block state root validation failed",
		}).Error("Block state root validation failed")
		return false
	} else {
		return true
	}
}
