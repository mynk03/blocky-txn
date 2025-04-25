// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package execution_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/proto/harbor"
	"blockchain-simulator/transaction"
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// HarborServer implements the Harbor API server
type HarborServer struct {
	harbor.UnimplementedHarborAPIServer
	txPool        *transaction.TransactionPool
	chain         *blockchain.Blockchain
	logger        *logrus.Logger
	validatorAddr string
}

// NewHarborServer creates a new Harbor server
func NewHarborServer(txPool *transaction.TransactionPool, chain *blockchain.Blockchain, validatorAddr string, logger *logrus.Logger) *HarborServer {
	if logger == nil {
		logger = logrus.New()
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
		logger.SetLevel(logrus.InfoLevel)
	}

	return &HarborServer{
		txPool:        txPool,
		chain:         chain,
		logger:        logger,
		validatorAddr: validatorAddr,
	}
}

// CreateBlock implements the HarborAPI.CreateBlock RPC method
func (s *HarborServer) CreateBlock(ctx context.Context, req *harbor.BlockCreationRequest) (*harbor.BlockCreationResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"max_txs":   req.MaxTransactions,
		"validator": req.ValidatorAddress,
	}).Info("Received CreateBlock request")

	// validate the validator address
	if s.validatorAddr != req.ValidatorAddress || s.validatorAddr == "" {
		return &harbor.BlockCreationResponse{
			ErrorMessage: "Invalid validator address",
		}, nil
	}

	// Get transactions from pool
	transactions := s.txPool.GetAllTransactions()
	if len(transactions) == 0 {
		return &harbor.BlockCreationResponse{
			ErrorMessage: "No transactions in pool",
		}, nil
	}

	// Limit transactions if max_transactions is specified
	if req.MaxTransactions > 0 && uint32(len(transactions)) > req.MaxTransactions {
		transactions = transactions[:req.MaxTransactions]
	}

	// Create new block
	prevBlock := s.chain.GetLatestBlock()

	// create a new block with the transactions
	newBlock := blockchain.CreateBlock(transactions, prevBlock)
	newBlock.Validator = s.validatorAddr

	// Process the transactions on the validator's state trie
	blockchain.ProcessBlock(newBlock, s.chain.StateTrie)

	// Update the state root
	newBlock.StateRoot = s.chain.StateTrie.RootHash()

	// Calculate block hash
	newBlock.Hash = blockchain.CalculateBlockHash(newBlock)

	// remove the transactions from the txn pool to avoid double spending
	// get the transaction hashes
	txHashes := make([]string, len(newBlock.Transactions))
	for i, tx := range newBlock.Transactions {
		txHashes[i] = tx.TransactionHash
	}

	// update the transaction status to success
	for _, tx := range transactions {
		tx.Status = transaction.Success

		// store the txn in memory
		s.chain.Storage.PutTransaction(tx)
	}

	// remove the transactions from the txn pool
	s.txPool.RemoveBulkTransactions(txHashes)

	// Convert to protobuf BlockData
	blockData := &harbor.BlockData{
		Index:        newBlock.Index,
		Timestamp:    newBlock.Timestamp,
		PrevHash:     newBlock.PrevHash,
		Hash:         newBlock.Hash,
		StateRoot:    newBlock.StateRoot,
		Validator:    newBlock.Validator,
		Transactions: make([]*harbor.TransactionData, len(newBlock.Transactions)),
	}

	// Convert transactions to protobuf format
	for i, tx := range newBlock.Transactions {
		fmt.Println("sender: ", tx.Sender.Hex())
		fmt.Println("receiver: ", tx.Receiver.Hex())
		fmt.Println("amount: ", tx.Amount)
		fmt.Println("nonce: ", tx.Nonce)
		fmt.Println("transaction hash: ", tx.TransactionHash)
		fmt.Println("signature: ", tx.Signature)
		blockData.Transactions[i] = &harbor.TransactionData{
			From:            tx.Sender.Hex(),
			To:              tx.Receiver.Hex(),
			Amount:          tx.Amount,
			Nonce:           tx.Nonce,
			TransactionHash: tx.TransactionHash,
			Signature:       hex.EncodeToString(tx.Signature),
		}
	}

	return &harbor.BlockCreationResponse{
		Block: blockData,
	}, nil
}

// ValidateBlock implements the HarborAPI.ValidateBlock RPC method
func (s *HarborServer) ValidateBlock(ctx context.Context, req *harbor.BlockValidationRequest) (*harbor.ValidationResult, error) {
	s.logger.WithFields(logrus.Fields{
		"block_hash": req.Block.Hash,
		"index":      req.Block.Index,
	}).Info("Received ValidateBlock request")

	// Get the last block
	lastBlock := s.chain.GetLatestBlock()

	// Check block linkage
	if lastBlock.Hash != req.Block.PrevHash || req.Block.Index != lastBlock.Index+1 || req.Block.PrevHash == "" {
		return &harbor.ValidationResult{
			Valid:        false,
			ErrorMessage: "Block linkage validation failed",
		}, nil
	}

	// Convert protobuf BlockData to blockchain.Block
	block := blockchain.Block{
		Index:        req.Block.Index,
		Timestamp:    req.Block.Timestamp,
		PrevHash:     req.Block.PrevHash,
		Hash:         req.Block.Hash,
		StateRoot:    req.Block.StateRoot,
		Validator:    req.Block.Validator,
		Transactions: make([]transaction.Transaction, len(req.Block.Transactions)),
	}

	// Convert transactions
	for i, txData := range req.Block.Transactions {
		block.Transactions[i] = transaction.Transaction{
			Sender:          common.HexToAddress(txData.From),
			Receiver:        common.HexToAddress(txData.To),
			Amount:          txData.Amount,
			Nonce:           txData.Nonce,
			TransactionHash: txData.TransactionHash,
			Signature:       []byte(txData.Signature),
		}
	}

	// create a copy of the state trie to avoid modifying the original state trie
	tempStateTrie := s.chain.StateTrie.Copy()

	// process the transaction on the validator's state trie
	blockchain.ProcessBlock(block, tempStateTrie)

	// validate the block state root
	if block.StateRoot != tempStateTrie.RootHash() {
		logrus.WithFields(logrus.Fields{
			"type":  "block_validation",
			"error": "Block state root validation failed",
		}).Error("Block state root validation failed")
		return &harbor.ValidationResult{
			Valid:        false,
			ErrorMessage: "Block state root validation failed",
		}, nil
	}

	blockchain.ProcessBlock(block, s.chain.StateTrie)
	s.chain.AddBlock(block)

	// remove the transactions from the txn pool to avoid double spending
	// get the transaction hashes
	txHashes := make([]string, len(block.Transactions))
	for i, tx := range block.Transactions {
		txHashes[i] = tx.TransactionHash
	}
	// remove the transactions from the txn pool
	s.txPool.RemoveBulkTransactions(txHashes)

	return &harbor.ValidationResult{
		Valid: true,
	}, nil

}

// StartServer starts the gRPC server
func (s *HarborServer) StartServer(port string) error {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	server := grpc.NewServer()
	harbor.RegisterHarborAPIServer(server, s)
	reflection.Register(server) // Enable reflection for debugging

	s.logger.WithField("port", port).Info("Starting Harbor gRPC server")
	if err := server.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}
