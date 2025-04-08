package execution_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/proto/harbor"
	"blockchain-simulator/transaction"
	"blockchain-simulator/validator"
	"context"
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
	txPool *transaction.TransactionPool
	chain  *blockchain.Blockchain
	logger *logrus.Logger
}

// NewHarborServer creates a new Harbor server
func NewHarborServer(txPool *transaction.TransactionPool, chain *blockchain.Blockchain, logger *logrus.Logger) *HarborServer {
	if logger == nil {
		logger = logrus.New()
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
		logger.SetLevel(logrus.InfoLevel)
	}

	return &HarborServer{
		txPool: txPool,
		chain:  chain,
		logger: logger,
	}
}

// CreateBlock implements the HarborAPI.CreateBlock RPC method
func (s *HarborServer) CreateBlock(ctx context.Context, req *harbor.BlockCreationRequest) (*harbor.BlockCreationResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"prev_block_hash": req.PrevBlockHash,
		"max_txs":         req.MaxTransactions,
		"validator":       req.ValidatorAddress,
	}).Info("Received CreateBlock request")

	// Validate validator address
	validatorAddr := common.HexToAddress(req.ValidatorAddress)
	if validatorAddr == (common.Address{}) {
		return nil, fmt.Errorf("invalid validator address")
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

	// check the validator State are updated
	if req.PrevBlockHash != prevBlock.Hash {
		return &harbor.BlockCreationResponse{
			ErrorMessage: "Previous block hash does not match",
		}, nil
	}

	// block := validator.CreateNewBlock(transactions, prevBlock)
	block := blockchain.CreateBlock(transactions, prevBlock) // TODO: use validator.CreateNewBlock
	block.Validator = validatorAddr.Hex()

	// Calculate block hash
	block.Hash = blockchain.CalculateBlockHash(block)

	// Convert to protobuf BlockData
	blockData := &harbor.BlockData{
		Index:        block.Index,
		Timestamp:    block.Timestamp,
		PrevHash:     block.PrevHash,
		Hash:         block.Hash,
		StateRoot:    block.StateRoot,
		Validator:    block.Validator,
		Transactions: make([]*harbor.TransactionData, len(block.Transactions)),
	}

	// Convert transactions to protobuf format
	for i, tx := range block.Transactions {
		blockData.Transactions[i] = &harbor.TransactionData{
			From:            tx.Sender.Hex(),
			To:              tx.Receiver.Hex(),
			Amount:          tx.Amount,
			Nonce:           tx.Nonce,
			TransactionHash: tx.TransactionHash,
			Signature:       string(tx.Signature),
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

	// Create a validator to validate the block
	validator := validator.NewValidator(common.HexToAddress(req.Block.Validator), s.txPool, s.chain)

	// Validate block
	if !validator.ValidateBlock(block) {
		return &harbor.ValidationResult{
			Valid:        false,
			ErrorMessage: "Block validation failed",
		}, nil
	}

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
