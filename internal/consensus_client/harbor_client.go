// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus_client

import (
	"blockchain-simulator/internal/blockchain"
	"blockchain-simulator/pkg/proto/harbor"
	"blockchain-simulator/internal/transaction"
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ExecutionClient represents the interface for interacting with the execution client (Harbor service)
type ExecutionClient interface {
	RequestBlockCreation(ctx context.Context, validatorAddress common.Address, maxTransactions uint32) (*blockchain.Block, error)
	ValidateBlock(ctx context.Context, block *blockchain.Block) (bool, error)
	Close() error
}

// HarborClient handles communication with the execution client via the Harbor gRPC service
// This is similar to how Ethereum's consensus client communicates with the execution client via the ENGINE API
type HarborClient struct {
	// Connection to the execution client
	conn *grpc.ClientConn

	// Client for the harbor service
	client harbor.HarborAPIClient

	// Logger for the harbor client
	logger *logrus.Logger

	// Address of the execution client
	address string
}

// NewHarborClient creates a new harbor client
func NewHarborClient(address string, logger *logrus.Logger) (*HarborClient, error) {
	if logger == nil {
		logger = logrus.New()
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
		logger.SetLevel(logrus.InfoLevel)
	}

	// Create a new client
	client := &HarborClient{
		address: address,
		logger:  logger,
	}

	// Connect to the execution client
	err := client.Connect()
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Connect establishes a connection to the execution client
func (c *HarborClient) Connect() error {
	// Set up connection to the execution client using insecure credentials (for development only)
	// In production, use proper TLS credentials
	conn, err := grpc.NewClient(c.address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to execution client: %w", err)
	}

	c.conn = conn
	c.client = harbor.NewHarborAPIClient(conn)
	c.logger.WithField("address", c.address).Info("Connected to execution client via Harbor service")

	return nil
}

// Close closes the connection to the execution client
func (c *HarborClient) Close() error {
	if c.conn != nil {
		err := c.conn.Close()
		if err != nil {
			return fmt.Errorf("failed to close connection to execution client: %w", err)
		}
	}
	return nil
}

// RequestBlockCreation asks the execution client to create a new block from its transaction pool
func (c *HarborClient) RequestBlockCreation(ctx context.Context, validatorAddress common.Address, maxTransactions uint32) (*blockchain.Block, error) {
	c.logger.WithFields(logrus.Fields{
		"validatorAddress": validatorAddress.Hex(),
		"maxTransactions":  maxTransactions,
	}).Info("Requesting block creation from execution client via Harbor")

	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Make the gRPC call
	resp, err := c.client.CreateBlock(timeoutCtx, &harbor.BlockCreationRequest{
		ValidatorAddress: validatorAddress.Hex(),
		MaxTransactions:  maxTransactions,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to request block creation: %w", err)
	}

	// Check for error in response
	if resp.ErrorMessage != "" {
		return nil, fmt.Errorf("execution client error: %s", resp.ErrorMessage)
	}

	// If no block was created (e.g., no transactions available)
	if resp.Block == nil {
		return nil, fmt.Errorf("no block was created")
	}

	// Convert proto block to domain block
	block := &blockchain.Block{
		Index:        resp.Block.Index,
		Timestamp:    resp.Block.Timestamp,
		PrevHash:     resp.Block.PrevHash,
		Hash:         resp.Block.Hash,
		StateRoot:    resp.Block.StateRoot,
		Validator:    resp.Block.Validator,
		Transactions: make([]transaction.Transaction, 0, len(resp.Block.Transactions)),
	}

	// Convert transactions
	for _, tx := range resp.Block.Transactions {
		// Convert string addresses to common.Address
		fromAddr := common.HexToAddress(tx.From)
		toAddr := common.HexToAddress(tx.To)

		// Convert string signature to []byte if needed
		var signature []byte
		if tx.Signature != "" {
			// This is just a placeholder - the actual conversion depends on how signatures are stored in your proto
			signature = []byte(tx.Signature)
		}

		domainTx := transaction.Transaction{
			Sender:          fromAddr,
			Receiver:        toAddr,
			Amount:          tx.Amount,
			Nonce:           tx.Nonce,
			TransactionHash: tx.TransactionHash,
			Signature:       signature,
		}
		block.Transactions = append(block.Transactions, domainTx)
	}

	c.logger.WithFields(logrus.Fields{
		"blockHash":  block.Hash,
		"blockIndex": block.Index,
		"txCount":    len(block.Transactions),
	}).Info("Successfully created block from execution client")

	return block, nil
}

// ValidateBlock asks the execution client to validate a block and its transactions
func (c *HarborClient) ValidateBlock(ctx context.Context, block *blockchain.Block) (bool, error) {
	c.logger.WithFields(logrus.Fields{
		"blockHash":  block.Hash,
		"blockIndex": block.Index,
	}).Info("Requesting block validation from execution client via Harbor")

	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Convert domain block to proto block
	protoBlock := &harbor.BlockData{
		Index:        block.Index,
		Timestamp:    block.Timestamp,
		PrevHash:     block.PrevHash,
		Hash:         block.Hash,
		StateRoot:    block.StateRoot,
		Validator:    block.Validator,
		Transactions: make([]*harbor.TransactionData, 0, len(block.Transactions)),
	}

	// Convert transactions
	for _, tx := range block.Transactions {
		// Convert addresses to strings
		fromStr := tx.Sender.Hex()
		toStr := tx.Receiver.Hex()

		// Convert signature to string if needed
		var signatureStr string
		if tx.Signature != nil {
			// This is just a placeholder - the actual conversion depends on how signatures are stored in your domain model
			signatureStr = string(tx.Signature)
		}

		protoTx := &harbor.TransactionData{
			From:            fromStr,
			To:              toStr,
			Amount:          tx.Amount,
			Nonce:           tx.Nonce,
			TransactionHash: tx.TransactionHash,
			Signature:       signatureStr,
		}
		protoBlock.Transactions = append(protoBlock.Transactions, protoTx)
	}

	// Make the gRPC call
	resp, err := c.client.ValidateBlock(timeoutCtx, &harbor.BlockValidationRequest{
		Block: protoBlock,
	})
	if err != nil {
		return false, fmt.Errorf("failed to request block validation: %w", err)
	}

	if !resp.Valid {
		c.logger.WithFields(logrus.Fields{
			"blockHash":    block.Hash,
			"errorMessage": resp.ErrorMessage,
		}).Warn("Block validation failed")
		return false, fmt.Errorf("block validation failed: %s", resp.ErrorMessage)
	}

	c.logger.WithField("blockHash", block.Hash).Info("Block validation successful")
	return true, nil
}
