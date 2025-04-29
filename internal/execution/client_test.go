// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package execution

import (
	"blockchain-simulator/internal/blockchain"
	"blockchain-simulator/internal/transaction"
	"blockchain-simulator/internal/wallet"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type ExecutionClientTestSuite struct {
	suite.Suite
	client1 *ExecutionClient
	client2 *ExecutionClient
	txPool1 *transaction.TransactionPool
	txPool2 *transaction.TransactionPool
	chain1  *blockchain.Blockchain
	chain2  *blockchain.Blockchain
	wallet1 *wallet.MockWallet // Validator wallet for node 1
	wallet2 *wallet.MockWallet // Validator wallet for node 2
	logger  *logrus.Logger
}

func (suite *ExecutionClientTestSuite) SetupTest() {
	var err error
	fmt.Println("Setting up test environment...")

	// Create test logger
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.DebugLevel)

	// Create test data directory
	testDataDir := "./testdata"
	err = os.MkdirAll(testDataDir, 0755)
	suite.Require().NoError(err, "Failed to create test data directory")

	// Create validator wallets
	suite.wallet1, err = wallet.NewMockWallet()
	suite.Require().NoError(err, "Failed to create validator wallet1")
	suite.wallet2, err = wallet.NewMockWallet()
	suite.Require().NoError(err, "Failed to create validator wallet2")

	// Create transaction pools
	suite.txPool1 = transaction.NewTransactionPool()
	suite.txPool2 = transaction.NewTransactionPool()

	// Create storage for blockchains
	storage1, err := blockchain.NewLevelDBStorage(filepath.Join(testDataDir, "node1"))
	suite.Require().NoError(err, "Failed to create storage1")
	storage2, err := blockchain.NewLevelDBStorage(filepath.Join(testDataDir, "node2"))
	suite.Require().NoError(err, "Failed to create storage2")

	// Create blockchains with initial accounts
	accounts := []string{
		suite.wallet1.GetAddress().Hex(),
		suite.wallet2.GetAddress().Hex(),
	}
	amounts := []uint64{1000, 1000}

	suite.chain1 = blockchain.NewBlockchain(storage1, accounts, amounts)
	suite.chain2 = blockchain.NewBlockchain(storage2, accounts, amounts)

	// Create harbor servers
	harborServer1 := NewHarborServer(suite.txPool1, suite.chain1, accounts[0], suite.logger)
	harborServer2 := NewHarborServer(suite.txPool2, suite.chain2, accounts[1], suite.logger)

	// Create execution clients with longer timeouts
	suite.client1, err = NewExecutionClient(
		"/ip4/127.0.0.1/tcp/5051", // Use fixed port for client1
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		harborServer1,
		suite.logger,
	)
	suite.Require().NoError(err, "Failed to create client1")

	suite.client2, err = NewExecutionClient(
		"/ip4/127.0.0.1/tcp/5052", // Use fixed port for client2
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		harborServer2,
		suite.logger,
	)
	suite.Require().NoError(err, "Failed to create client2")

	// Create servers for clients
	server1 := NewServer(suite.client1)
	server2 := NewServer(suite.client2)

	// Start client1 first
	err = suite.client1.Start("5051", server1, "8081")
	suite.Require().NoError(err, "Failed to start client1")
	time.Sleep(2 * time.Second) // Wait longer for client1 to initialize

	// Start client2 and connect to client1
	err = suite.client2.Start("5052", server2, "8082")
	suite.Require().NoError(err, "Failed to start client2")
	time.Sleep(2 * time.Second) // Wait longer for client2 to initialize

	// Explicitly connect client2 to client1
	client1Addr := fmt.Sprintf("/ip4/127.0.0.1/tcp/5051/p2p/%s", suite.client1.host.ID().String())
	err = suite.client2.ConnectToPeer(client1Addr)
	suite.Require().NoError(err, "Failed to connect client2 to client1")

	// Wait for peer connections to establish
	maxAttempts := 10
	attempts := 0
	connected := false
	for attempts < maxAttempts {
		time.Sleep(2 * time.Second)
		peers1 := suite.client1.GetPeers()
		peers2 := suite.client2.GetPeers()

		if len(peers1) == 1 && len(peers2) == 1 {
			// Verify actual connection
			if suite.client1.IsConnectedTo(suite.client2.GetAddress()) &&
				suite.client2.IsConnectedTo(suite.client1.GetAddress()) {
				fmt.Println("Connected to all discovered peers")
				connected = true
				break
			}
		}
		attempts++
	}

	if !connected {
		suite.Fail("Failed to establish peer connections within timeout")
	}

	// Additional verification of peer connection
	peers1 := suite.client1.GetPeers()
	peers2 := suite.client2.GetPeers()
	suite.Require().Equal(1, len(peers1), "client1 should have exactly 1 peer")
	suite.Require().Equal(1, len(peers2), "client2 should have exactly 1 peer")

	// Wait for pubsub to initialize
	time.Sleep(2 * time.Second)
}

func (suite *ExecutionClientTestSuite) TearDownTest() {
	fmt.Println("\n ** Tearing down test environment...")

	// Stop clients in reverse order
	if suite.client2 != nil {
		fmt.Println("Stopping client2...")
		suite.client2.Stop()
		time.Sleep(500 * time.Millisecond)
	}
	if suite.client1 != nil {
		fmt.Println("Stopping client1...")
		suite.client1.Stop()
		time.Sleep(500 * time.Millisecond)
	}

	// Clean up storage
	if suite.chain1 != nil && suite.chain1.Storage != nil {
		fmt.Println("Closing chain1 storage...")
		err := suite.chain1.Storage.Close()
		if err != nil {
			fmt.Printf("Error closing chain1 storage: %v\n", err)
		}
	}
	if suite.chain2 != nil && suite.chain2.Storage != nil {
		fmt.Println("Closing chain2 storage...")
		err := suite.chain2.Storage.Close()
		if err != nil {
			fmt.Printf("Error closing chain2 storage: %v\n", err)
		}
	}

	// Clean up test data directory
	fmt.Println("Removing test data directory...")
	err := os.RemoveAll("./testdata")
	if err != nil {
		fmt.Printf("Error removing test data directory: %v\n", err)
	}

	// Give time for the clients to stop
	time.Sleep(500 * time.Millisecond)
}

func TestExecutionClientTestSuite(t *testing.T) {
	suite.Run(t, new(ExecutionClientTestSuite))
}

func (suite *ExecutionClientTestSuite) TestTransactionPropagation() {
	fmt.Println("\nTesting transaction propagation between nodes...")

	// Ensure clients are initialized
	suite.Require().NotNil(suite.client1, "client1 should not be nil")
	suite.Require().NotNil(suite.client2, "client2 should not be nil")

	// Verify peer connections
	peers1 := suite.client1.GetPeers()
	peers2 := suite.client2.GetPeers()
	suite.Equal(1, len(peers1), "client1 should have 1 peer")
	suite.Equal(1, len(peers2), "client2 should have 1 peer")

	// Create a simple transaction
	tx := transaction.Transaction{
		Sender:    suite.wallet1.GetAddress(),
		Receiver:  suite.wallet2.GetAddress(),
		Amount:    100,
		Nonce:     0,
		Status:    transaction.Pending,
		Timestamp: uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	signature, err := suite.wallet1.SignTransaction(common.HexToHash(tx.TransactionHash))
	suite.Require().NoError(err, "Failed to sign transaction")
	tx.Signature = signature

	// Broadcast transaction from client1
	err = suite.client1.BroadcastTransaction(tx)
	suite.Require().NoError(err, "Failed to broadcast transaction")

	// Wait longer for transaction to be processed and propagated
	time.Sleep(2 * time.Second)

	// Verify transaction was added to client1's pool first
	suite.True(suite.client1.txPool.HasTransaction(tx.TransactionHash),
		"Transaction should be in client1's pool")

	// Verify transaction was propagated to client2's pool
	suite.True(suite.client2.txPool.HasTransaction(tx.TransactionHash),
		"Transaction should be in client2's pool")

	// Get and verify transaction details from both pools
	tx1, exists1 := suite.client1.txPool.GetTransaction(tx.TransactionHash)
	suite.True(exists1, "Transaction should exist in client1's pool")

	// Verify transaction details are consistent
	suite.Equal(tx.Sender, tx1.Sender, "Sender should match in client2's pool")
	suite.Equal(tx.Receiver, tx1.Receiver, "Receiver should match in client2's pool")
	suite.Equal(tx.Amount, tx1.Amount, "Amount should match in client2's pool")
	suite.Equal(tx.Nonce, tx1.Nonce, "Nonce should match in client2's pool")

	tx2, exists2 := suite.client2.txPool.GetTransaction(tx.TransactionHash)
	suite.True(exists2, "Transaction should exist in client2's pool")

	// Verify transaction details are consistent
	suite.Equal(tx.Sender, tx2.Sender, "Sender should match in client2's pool")
	suite.Equal(tx.Receiver, tx2.Receiver, "Receiver should match in client2's pool")
	suite.Equal(tx.Amount, tx2.Amount, "Amount should match in client2's pool")
	suite.Equal(tx.Nonce, tx2.Nonce, "Nonce should match in client2's pool")

}
