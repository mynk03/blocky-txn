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

// ProposeBlock validates and adds transactions from the transaction pool to the blockchain
func (v *Validator) ProposeBlock() blockchain.Block {
	// Get all pending transaction from the transaction pool
	pendingTxs := v.TransactionPool.GetPendingTransactions()

	validTransactions := []transactions.Transaction{}
	for _, tx := range pendingTxs {
		if status, err := tx.ValidateWithState(v.LocalChain.StateTrie); !status {
			// Log the error gracefully (no panic)
			logrus.WithFields(logrus.Fields{
				"type":  "transaction_validation",
				"error": err,
			}).Error("Transaction_validation_failed")
			continue
		}

		// Convert transactions.Transaction to blockchain.Transaction
		blockchainTx := transactions.Transaction{
			TransactionHash: tx.TransactionHash,
			From:            tx.From,
			To:              tx.To,
			Amount:          tx.Amount,
			Nonce:           tx.Nonce,
			Timestamp:       tx.Timestamp,
			Status:          tx.Status,
		}
		validTransactions = append(validTransactions, blockchainTx)
	}
	// Create a new block with the valid transaction
	prevBlock := v.LocalChain.Chain[len(v.LocalChain.Chain)-1]
	newBlock := blockchain.CreateBlock(validTransactions, prevBlock)

	fmt.Println("here state trie before processing block", v.LocalChain.StateTrie.RootHash())
	// process the transaction on the validator 's state trie
	transactions.ProcessTransactions(newBlock.Transactions, v.LocalChain.StateTrie)

	fmt.Println("here state trie after processing block", v.LocalChain.StateTrie.RootHash())


	// update the state root
	newBlock.StateRoot = v.LocalChain.StateTrie.RootHash()

	// return Block
	return newBlock
}

func (v *Validator) ValidateBlock(block *blockchain.Block) bool {

	// Check block linkage
	if block.PrevHash != block.Hash || block.Index != block.Index+1 {
		return false
	}

	// process the transaction on the validator's state trie
	transactions.ProcessTransactions(block.Transactions, v.LocalChain.StateTrie)

	// validate the block state root
	if block.StateRoot != v.LocalChain.StateTrie.RootHash() {
		return false
	} else {
		return true
	}
}
