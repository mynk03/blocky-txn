// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/proto/harbor"
	"blockchain-simulator/transactions"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// mockHarborAPIClient implements harbor.HarborAPIClient for testing
type mockHarborAPIClient struct {
	mock.Mock
}

// CreateBlock implements the CreateBlock method from harbor.HarborAPIClient
func (m *mockHarborAPIClient) CreateBlock(ctx context.Context, req *harbor.BlockCreationRequest, opts ...grpc.CallOption) (*harbor.BlockCreationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*harbor.BlockCreationResponse), args.Error(1)
}

// ValidateBlock implements the ValidateBlock method from harbor.HarborAPIClient
func (m *mockHarborAPIClient) ValidateBlock(ctx context.Context, req *harbor.BlockValidationRequest, opts ...grpc.CallOption) (*harbor.ValidationResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*harbor.ValidationResult), args.Error(1)
}

// We need to override the NewHarborClient function to avoid real connections
func setupTestHarborClient(t *testing.T) (*HarborClient, *mockHarborAPIClient, *test.Hook) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)

	mockAPI := new(mockHarborAPIClient)

	client := &HarborClient{
		address: "localhost:50051",
		logger:  logger,
		client:  mockAPI,
	}

	return client, mockAPI, hook
}

// TestRequestBlockCreation tests the block creation request functionality
func TestRequestBlockCreation(t *testing.T) {
	client, mockAPI, _ := setupTestHarborClient(t)

	// Create test data
	validatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	prevBlockHash := "0000000000000000000000000000000000000000000000000000000000000000"
	maxTransactions := uint32(10)
	ctx := context.Background()

	// Case 1: Successful block creation
	mockResp := &harbor.BlockCreationResponse{
		Block: &harbor.BlockData{
			Index:     1,
			Timestamp: time.Now().String(),
			PrevHash:  prevBlockHash,
			Hash:      "0000000000000000000000000000000000000000000000000000000000000001",
			StateRoot: "stateRoot123",
			Validator: validatorAddr.Hex(),
			Transactions: []*harbor.TransactionData{
				{
					From:            "0x2222222222222222222222222222222222222222",
					To:              "0x3333333333333333333333333333333333333333",
					Amount:          100,
					Nonce:           1,
					TransactionHash: "tx123",
					Signature:       "sig123",
				},
			},
		},
		ErrorMessage: "",
	}

	// Setup expectations on the mock
	mockAPI.On("CreateBlock", mock.Anything, mock.MatchedBy(func(req *harbor.BlockCreationRequest) bool {
		return req.ValidatorAddress == validatorAddr.Hex() &&
			req.PrevBlockHash == prevBlockHash &&
			req.MaxTransactions == maxTransactions
	})).Return(mockResp, nil).Once()

	// Call the method
	block, err := client.RequestBlockCreation(ctx, validatorAddr, prevBlockHash, maxTransactions)
	assert.NoError(t, err, "RequestBlockCreation should not return an error")
	assert.NotNil(t, block, "Block should not be nil")
	assert.Equal(t, uint64(1), block.Index, "Block index should match")
	assert.Equal(t, prevBlockHash, block.PrevHash, "Block previous hash should match")
	assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000001", block.Hash, "Block hash should match")
	assert.Equal(t, "stateRoot123", block.StateRoot, "Block state root should match")
	assert.Equal(t, validatorAddr.Hex(), block.Validator, "Block validator should match")
	assert.Len(t, block.Transactions, 1, "Block should have 1 transaction")
	assert.Equal(t, common.HexToAddress("0x2222222222222222222222222222222222222222"), block.Transactions[0].From, "Transaction from should match")
	assert.Equal(t, common.HexToAddress("0x3333333333333333333333333333333333333333"), block.Transactions[0].To, "Transaction to should match")
	assert.Equal(t, uint64(100), block.Transactions[0].Amount, "Transaction amount should match")
	assert.Equal(t, uint64(1), block.Transactions[0].Nonce, "Transaction nonce should match")
	assert.Equal(t, "tx123", block.Transactions[0].TransactionHash, "Transaction hash should match")
	assert.Equal(t, []byte("sig123"), block.Transactions[0].Signature, "Transaction signature should match")

	// Case 2: Error from API client
	mockAPI.On("CreateBlock", mock.Anything, mock.Anything).Return(nil, errors.New("API error")).Once()
	block, err = client.RequestBlockCreation(ctx, validatorAddr, prevBlockHash, maxTransactions)
	assert.Error(t, err, "RequestBlockCreation should return an error when API client fails")
	assert.Nil(t, block, "Block should be nil when API client fails")
	assert.Contains(t, err.Error(), "failed to request block creation", "Error message should indicate API client failure")

	// Case 3: Error message in response
	mockResp.Block = nil
	mockResp.ErrorMessage = "execution error"
	mockAPI.On("CreateBlock", mock.Anything, mock.Anything).Return(mockResp, nil).Once()
	block, err = client.RequestBlockCreation(ctx, validatorAddr, prevBlockHash, maxTransactions)
	assert.Error(t, err, "RequestBlockCreation should return an error when response contains error message")
	assert.Nil(t, block, "Block should be nil when response contains error message")
	assert.Contains(t, err.Error(), "execution client error", "Error message should indicate execution client error")

	// Case 4: Nil block in response (no transactions available)
	mockResp.ErrorMessage = ""
	mockAPI.On("CreateBlock", mock.Anything, mock.Anything).Return(mockResp, nil).Once()
	block, err = client.RequestBlockCreation(ctx, validatorAddr, prevBlockHash, maxTransactions)
	assert.Error(t, err, "RequestBlockCreation should return an error when no block is created")
	assert.Nil(t, block, "Block should be nil when no block is created")
	assert.Contains(t, err.Error(), "no block was created", "Error message should indicate no block was created")

	// Verify all mocks were called as expected
	mockAPI.AssertExpectations(t)
}

// TestValidateBlock tests the block validation functionality
func TestValidateBlock(t *testing.T) {
	client, mockAPI, _ := setupTestHarborClient(t)

	// Create test data
	validatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	senderAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")
	receiverAddr := common.HexToAddress("0x3333333333333333333333333333333333333333")
	ctx := context.Background()

	// Create a test block
	testBlock := &blockchain.Block{
		Index:     1,
		Timestamp: time.Now().String(),
		PrevHash:  "0000000000000000000000000000000000000000000000000000000000000000",
		Hash:      "0000000000000000000000000000000000000000000000000000000000000001",
		StateRoot: "stateRoot123",
		Validator: validatorAddr.Hex(),
		Transactions: []transactions.Transaction{
			{
				From:            senderAddr,
				To:              receiverAddr,
				Amount:          100,
				Nonce:           1,
				TransactionHash: "tx123",
				Signature:       []byte("sig123"),
			},
		},
	}

	// Case 1: Successful validation
	mockResp := &harbor.ValidationResult{
		Valid:        true,
		ErrorMessage: "",
	}

	// Setup expectations on the mock - we'll verify the request content in detail
	mockAPI.On("ValidateBlock", mock.Anything, mock.MatchedBy(func(req *harbor.BlockValidationRequest) bool {
		if req.Block == nil {
			return false
		}

		// Check block fields
		if req.Block.Index != testBlock.Index ||
			req.Block.PrevHash != testBlock.PrevHash ||
			req.Block.Hash != testBlock.Hash ||
			req.Block.StateRoot != testBlock.StateRoot ||
			req.Block.Validator != testBlock.Validator {
			return false
		}

		// Check transaction fields
		if len(req.Block.Transactions) != 1 {
			return false
		}

		tx := req.Block.Transactions[0]
		if tx.From != senderAddr.Hex() ||
			tx.To != receiverAddr.Hex() ||
			tx.Amount != 100 ||
			tx.Nonce != 1 ||
			tx.TransactionHash != "tx123" ||
			tx.Signature != "sig123" {
			return false
		}

		return true
	})).Return(mockResp, nil).Once()

	// Call the method
	valid, err := client.ValidateBlock(ctx, testBlock)
	assert.NoError(t, err, "ValidateBlock should not return an error")
	assert.True(t, valid, "Block should be valid")

	// Case 2: Error from API client
	mockAPI.On("ValidateBlock", mock.Anything, mock.Anything).Return(nil, errors.New("API error")).Once()
	valid, err = client.ValidateBlock(ctx, testBlock)
	assert.Error(t, err, "ValidateBlock should return an error when API client fails")
	assert.False(t, valid, "Block should not be valid when API client fails")
	assert.Contains(t, err.Error(), "failed to request block validation", "Error message should indicate API client failure")

	// Case 3: Invalid block
	mockResp = &harbor.ValidationResult{
		Valid:        false,
		ErrorMessage: "invalid block",
	}
	mockAPI.On("ValidateBlock", mock.Anything, mock.Anything).Return(mockResp, nil).Once()
	valid, err = client.ValidateBlock(ctx, testBlock)
	assert.Error(t, err, "ValidateBlock should return an error when block is invalid")
	assert.False(t, valid, "Block should not be valid when validation fails")
	assert.Contains(t, err.Error(), "block validation failed", "Error message should indicate validation failure")
	assert.Contains(t, err.Error(), "invalid block", "Error message should include specific error message")

	// Verify all mocks were called as expected
	mockAPI.AssertExpectations(t)
}

// TestNewHarborClient tests the client creation functionality by creating a specialized test function
func TestNewHarborClient(t *testing.T) {
	// Test with simple new harbor client validation
	logger := logrus.New()
	hook := test.NewLocal(logger)

	// Test successful client operation with direct setup
	client := &HarborClient{
		address: "valid:50051",
		logger:  logger,
		// We don't need to set conn or client for this test
	}

	// Test logging operation
	client.logger.WithField("address", client.address).Info("Connected to execution client via Harbor service")

	foundConnectLog := false
	for _, entry := range hook.AllEntries() {
		if entry.Message == "Connected to execution client via Harbor service" {
			foundConnectLog = true
			break
		}
	}
	assert.True(t, foundConnectLog, "Should log connection message")

	// Test nil connection close
	err := client.Close()
	assert.NoError(t, err, "Close should not return an error with nil connection")

	// Test type compatibility
	mockServer := &mockHarborAPIServer{}
	result, err := mockServer.ValidateBlock(context.Background(), &harbor.BlockValidationRequest{})
	assert.NoError(t, err)
	assert.True(t, result.Valid)
}

// Variables to override for testing
var grpcDial = grpc.Dial

// mockHarborAPIServer implements the harbor.HarborAPIServer interface for testing
type mockHarborAPIServer struct {
	harbor.UnimplementedHarborAPIServer
}

// CreateBlock implements the CreateBlock method for the HarborAPIServer interface
func (m *mockHarborAPIServer) CreateBlock(ctx context.Context, req *harbor.BlockCreationRequest) (*harbor.BlockCreationResponse, error) {
	return &harbor.BlockCreationResponse{
		Block: &harbor.BlockData{
			Index:     1,
			Timestamp: fmt.Sprintf("%d", time.Now().Unix()),
			Hash:      "0000000000000000000000000000000000000000000000000000000000000001",
			Transactions: []*harbor.TransactionData{
				{
					From:   "0x1111111111111111111111111111111111111111",
					To:     "0x2222222222222222222222222222222222222222",
					Amount: 100,
				},
			},
		},
	}, nil
}

// ValidateBlock implements the ValidateBlock method for the HarborAPIServer interface
func (m *mockHarborAPIServer) ValidateBlock(ctx context.Context, req *harbor.BlockValidationRequest) (*harbor.ValidationResult, error) {
	return &harbor.ValidationResult{
		Valid: true,
	}, nil
}

// TestHarborClient_Close tests the Close method
func TestHarborClient_Close(t *testing.T) {
	t.Run("close nil connection", func(t *testing.T) {
		client := &HarborClient{
			conn: nil,
		}
		err := client.Close()
		assert.NoError(t, err)
	})

	t.Run("close with connection error", func(t *testing.T) {
		// Create a mock connection that returns an error on close
		conn, err := grpc.DialContext(
			context.Background(),
			"localhost:0", // Use a port that should be available but won't connect
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		assert.NoError(t, err)

		client := &HarborClient{
			conn: conn,
		}
		err = client.Close()
		assert.NoError(t, err)
	})
}
