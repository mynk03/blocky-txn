package execution_client

import (
	"blockchain-simulator/transaction"
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/stretchr/testify/suite"
)

// ExecutionClientTestSuite defines the test suite for the ExecutionClient
// It contains two transaction pools and two execution clients to test peer-to-peer communication
type ExecutionClientTestSuite struct {
	suite.Suite
	txPool1 *transaction.TransactionPool // First transaction pool for client1
	txPool2 *transaction.TransactionPool // Second transaction pool for client2
	client1 *ExecutionClient              // First execution client
	client2 *ExecutionClient              // Second execution client
}

// SetupTest initializes the test environment before each test
// It creates two transaction pools and execution clients, starts them, and establishes a connection
func (suite *ExecutionClientTestSuite) SetupTest() {
	// Create transaction pools
	suite.txPool1 = transaction.NewTransactionPool()
	suite.txPool2 = transaction.NewTransactionPool()

	// Create execution clients
	var err error
	suite.client1, err = NewExecutionClient(suite.txPool1)
	suite.NoError(err)

	suite.client2, err = NewExecutionClient(suite.txPool2)
	suite.NoError(err)

	// Start both clients
	err = suite.client1.Start()
	suite.NoError(err)

	err = suite.client2.Start()
	suite.NoError(err)

	// Wait for clients to start
	time.Sleep(100 * time.Millisecond)

	// Get client1's address
	addr := suite.client1.GetAddress()
	suite.NotEmpty(addr)

	// Connect client2 to client1
	err = suite.client2.ConnectToPeer(addr)
	suite.NoError(err)

	// Wait for connection to establish
	time.Sleep(200 * time.Millisecond)

	// Verify connection
	suite.True(suite.client2.IsConnectedTo(addr))
	suite.Equal(1, len(suite.client1.GetPeers()))
}

// TearDownTest cleans up resources after each test
// It ensures both clients are properly stopped
func (suite *ExecutionClientTestSuite) TearDownTest() {
	if suite.client1 != nil {
		suite.client1.Stop()
	}
	if suite.client2 != nil {
		suite.client2.Stop()
	}
}

// TestExecutionClientSuite runs all tests in the suite
func TestExecutionClientSuite(t *testing.T) {
	suite.Run(t, new(ExecutionClientTestSuite))
}

// TestTransactionBroadcasting verifies that transactions are properly broadcasted between peers
// It creates a test transaction, broadcasts it from client1, and verifies it's received by client2
func (suite *ExecutionClientTestSuite) TestTransactionBroadcasting() {
	// Create a test transaction
	tx := transaction.Transaction{
		From:        common.HexToAddress("0x123"),
		To:          common.HexToAddress("0x456"),
		Amount:      100,
		Nonce:       0,
		BlockNumber: 0,
		Timestamp:   uint64(time.Now().Unix()),
		Status:      transaction.Pending,
	}

	// Generate transaction hash
	tx.TransactionHash = tx.GenerateHash()

	// Verify connection before broadcasting
	suite.True(suite.client2.IsConnectedTo(suite.client1.GetAddress()))

	// Broadcast transaction from client1
	err := suite.client1.BroadcastTransaction(tx)
	suite.NoError(err)

	// Wait for transaction to propagate
	time.Sleep(200 * time.Millisecond)

	// Check if transaction was received by client2
	pendingTxs := suite.txPool2.GetPendingTransactions()
	suite.NotEmpty(pendingTxs, "Expected pending transactions to be non-empty")
	suite.Equal(1, len(pendingTxs))
	if len(pendingTxs) > 0 {
		suite.Equal(tx.From, pendingTxs[0].From)
		suite.Equal(tx.To, pendingTxs[0].To)
		suite.Equal(tx.Amount, pendingTxs[0].Amount)
	}
}

// TestClientLifecycle verifies the proper startup and shutdown behavior of the client
func (suite *ExecutionClientTestSuite) TestClientLifecycle() {
	// Create a new client
	txPool := transaction.NewTransactionPool()
	client, err := NewExecutionClient(txPool)
	suite.NoError(err)

	// Start client
	err = client.Start()
	suite.NoError(err)

	// Stop client
	client.Stop()

	// Try to broadcast after stopping
	err = client.BroadcastTransaction(transaction.Transaction{})
	suite.Error(err)
	suite.Contains(err.Error(), "client is stopped")
}

// TestInvalidPeerConnection verifies that the client properly handles invalid peer connection attempts
func (suite *ExecutionClientTestSuite) TestInvalidPeerConnection() {
	// Create a new client
	txPool := transaction.NewTransactionPool()
	client, err := NewExecutionClient(txPool)
	suite.NoError(err)
	defer client.Stop()

	// Start client
	err = client.Start()
	suite.NoError(err)

	// Try to connect to invalid address
	err = client.ConnectToPeer("invalid:address")
	suite.Error(err)
}

// TestTransactionValidation verifies that invalid transactions are rejected
func (suite *ExecutionClientTestSuite) TestTransactionValidation() {
	// Create an invalid transaction (zero amount)
	invalidTx := transaction.Transaction{
		From:        common.HexToAddress("0x123"),
		To:          common.HexToAddress("0x456"),
		Amount:      0,
		Nonce:       0,
		BlockNumber: 0,
		Timestamp:   uint64(time.Now().Unix()),
		Status:      transaction.Pending,
	}

	// Try to broadcast invalid transaction
	err := suite.client1.BroadcastTransaction(invalidTx)
	suite.Error(err)
}

// TestErrorPaths verifies all error paths and return statements in the execution client
func (suite *ExecutionClientTestSuite) TestErrorPaths() {
	suite.Run("NewExecutionClient errors", func() {
		client, err := NewExecutionClient(nil)
		suite.Error(err)
		suite.Contains(err.Error(), "transaction pool cannot be nil")
		suite.Nil(client)
	})

	suite.Run("Start errors", func() {
		txPool := transaction.NewTransactionPool()
		client, err := NewExecutionClient(txPool)
		suite.NoError(err)
		defer client.Stop()

		err = client.Start()
		suite.NoError(err)

		client.Stop()

		err = client.Start()
		suite.Error(err)
		suite.Contains(err.Error(), "client is stopped")
	})

	suite.Run("ConnectToPeer errors", func() {
		txPool := transaction.NewTransactionPool()
		client, err := NewExecutionClient(txPool)
		suite.NoError(err)
		defer client.Stop()

		err = client.Start()
		suite.NoError(err)

		// Test empty address
		err = client.ConnectToPeer("")
		suite.Error(err)
		suite.Contains(err.Error(), "invalid address")

		// Test malformed address
		err = client.ConnectToPeer("invalid/address")
		suite.Error(err)
		suite.Contains(err.Error(), "must begin with /")

		// Test invalid peer ID
		err = client.ConnectToPeer("/ip4/127.0.0.1/tcp/1234/p2p/invalid")
		suite.Error(err)
		suite.Contains(err.Error(), "failed to parse multiaddr")

		// Test unreachable address
		err = client.ConnectToPeer("/ip4/192.168.1.999/tcp/1234/p2p/QmInvalidPeerID")
		suite.Error(err)
		suite.Contains(err.Error(), "invalid value")

		// Test connecting after client is stopped
		client.Stop()
		err = client.ConnectToPeer(suite.client1.GetAddress())
		suite.Error(err)
		suite.Contains(err.Error(), "client is stopped")
	})

	suite.Run("BroadcastTransaction errors", func() {
		txPool := transaction.NewTransactionPool()
		client, err := NewExecutionClient(txPool)
		suite.NoError(err)
		defer client.Stop()

		err = client.Start()
		suite.NoError(err)

		tx := transaction.Transaction{
			From:        common.HexToAddress("0x123"),
			To:          common.HexToAddress("0x456"),
			Amount:      100,
			Nonce:       0,
			BlockNumber: 0,
			Timestamp:   uint64(time.Now().Unix()),
			Status:      transaction.Pending,
		}

		// Test broadcasting without peers
		err = client.BroadcastTransaction(tx)
		suite.Error(err)
		suite.Contains(err.Error(), "no connected peers")

		// Test broadcasting after stopping
		client.Stop()
		err = client.BroadcastTransaction(tx)
		suite.Error(err)
		suite.Contains(err.Error(), "client is stopped")

		// Test invalid transaction fields
		invalidTxs := []transaction.Transaction{
			{
				To:        common.HexToAddress("0x456"),
				Amount:    100,
				Timestamp: uint64(time.Now().Unix()),
			},
			{
				From:      common.HexToAddress("0x123"),
				Amount:    100,
				Timestamp: uint64(time.Now().Unix()),
			},
			{
				From:      common.HexToAddress("0x123"),
				To:        common.HexToAddress("0x456"),
				Amount:    0,
				Timestamp: uint64(time.Now().Unix()),
			},
			{
				From:      common.HexToAddress("0x123"),
				To:        common.HexToAddress("0x456"),
				Amount:    100,
				Timestamp: 0,
			},
		}

		for _, invalidTx := range invalidTxs {
			err = client.BroadcastTransaction(invalidTx)
			suite.Error(err)
		}
	})

	suite.Run("broadcast errors", func() {
		txPool := transaction.NewTransactionPool()
		client, err := NewExecutionClient(txPool)
		suite.NoError(err)
		defer client.Stop()

		err = client.Start()
		suite.NoError(err)

		// Test broadcasting without peers
		msg := Message{
			Topic:   "transaction",
			Payload: json.RawMessage(`{}`),
			Type:    "transaction",
		}
		err = client.broadcast(TransactionProtocolID, msg)
		suite.Error(err)
		suite.Contains(err.Error(), "no connected peers")

		// Test invalid message format
		invalidMsg := Message{
			Topic:   "transaction",
			Payload: json.RawMessage(`{invalid json}`),
			Type:    "transaction",
		}
		err = client.broadcast(TransactionProtocolID, invalidMsg)
		suite.Error(err)
		suite.Contains(err.Error(), "no connected peers")

		// Test large message
		largePayload := make([]byte, 1024*1024*100) // 100MB payload
		largeMsg := Message{
			Topic:   "transaction",
			Payload: largePayload,
			Type:    "transaction",
		}
		err = client.broadcast(TransactionProtocolID, largeMsg)
		suite.Error(err)
		suite.Contains(err.Error(), "no connected peers")
	})

	suite.Run("handleTransactionStream errors", func() {
		txPool := transaction.NewTransactionPool()
		client, err := NewExecutionClient(txPool)
		suite.NoError(err)
		defer client.Stop()

		// Test invalid message format
		invalidTxData := json.RawMessage(`{"invalid": "transaction"}`)
		stream := &mockStream{
			reader: bytes.NewReader(invalidTxData),
		}

		client.handleTransactionStream(stream)
		suite.True(stream.closed)

		// Test invalid transaction data
		invalidTxData = json.RawMessage(`{"topic":"transaction","payload":{"invalid":"data"},"type":"transaction"}`)
		stream = &mockStream{
			reader: bytes.NewReader(invalidTxData),
		}

		client.handleTransactionStream(stream)
		suite.True(stream.closed)
	})

	suite.Run("validateTransaction errors", func() {
		txPool := transaction.NewTransactionPool()
		client, err := NewExecutionClient(txPool)
		suite.NoError(err)
		defer client.Stop()

		// Test various invalid transactions
		invalidTxs := []transaction.Transaction{
			{
				To:        common.HexToAddress("0x456"),
				Amount:    100,
				Timestamp: uint64(time.Now().Unix()),
			},
			{
				From:      common.HexToAddress("0x123"),
				Amount:    100,
				Timestamp: uint64(time.Now().Unix()),
			},
			{
				From:      common.HexToAddress("0x123"),
				To:        common.HexToAddress("0x456"),
				Amount:    0,
				Timestamp: uint64(time.Now().Unix()),
			},
			{
				From:      common.HexToAddress("0x123"),
				To:        common.HexToAddress("0x456"),
				Amount:    100,
				Timestamp: 0,
			},
		}

		for _, invalidTx := range invalidTxs {
			err = client.validateTransaction(invalidTx)
			suite.Error(err)
		}
	})
}

// mockStream implements network.Stream for testing
type mockStream struct {
	network.Stream
	reader io.Reader
	closed bool
}

func (m *mockStream) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m *mockStream) Close() error {
	m.closed = true
	return nil
}
