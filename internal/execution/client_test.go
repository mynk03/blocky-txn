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

var listenAddr = "/ip4/127.0.0.1/tcp/0"

type ExecutionClientTestSuite struct {
	suite.Suite
	client1       *ExecutionClient
	client2       *ExecutionClient
	client3       *ExecutionClient
	txPool1       *transaction.TransactionPool
	txPool2       *transaction.TransactionPool
	txPool3       *transaction.TransactionPool
	chain1        *blockchain.Blockchain
	chain2        *blockchain.Blockchain
	chain3        *blockchain.Blockchain
	wallet1       *wallet.MockWallet // Validator wallet for node 1
	wallet2       *wallet.MockWallet // Validator wallet for node 2
	wallet3       *wallet.MockWallet // Validator wallet for node 3
	logger        *logrus.Logger
	harborServer1 *HarborServer
	harborServer2 *HarborServer
	harborServer3 *HarborServer
	stakeAddress  common.Address
}

func (suite *ExecutionClientTestSuite) SetupTest() {
	var err error
	fmt.Println("Setting up test environment...")

	// Create test logger
	suite.logger = logrus.New()

	// Create test data directory
	testDataDir := "./testdata"
	err = os.MkdirAll(testDataDir, 0755)
	suite.Require().NoError(err, "Failed to create test data directory")

	// seting the stakeAddress
	suite.stakeAddress = common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create validator wallets
	suite.wallet1, err = wallet.NewMockWallet()
	suite.Require().NoError(err, "Failed to create validator wallet1")
	suite.wallet2, err = wallet.NewMockWallet()
	suite.Require().NoError(err, "Failed to create validator wallet2")
	suite.wallet3, err = wallet.NewMockWallet()
	suite.Require().NoError(err, "Failed to create validator wallet3")

	// Create transaction pools
	suite.txPool1 = transaction.NewTransactionPool()
	suite.txPool2 = transaction.NewTransactionPool()
	suite.txPool3 = transaction.NewTransactionPool()

	// Create storage for blockchains
	storage1, err := blockchain.NewLevelDBStorage(filepath.Join(testDataDir, "node1"))
	suite.Require().NoError(err, "Failed to create storage1")
	storage2, err := blockchain.NewLevelDBStorage(filepath.Join(testDataDir, "node2"))
	suite.Require().NoError(err, "Failed to create storage2")
	storage3, err := blockchain.NewLevelDBStorage(filepath.Join(testDataDir, "node3"))
	suite.Require().NoError(err, "Failed to create storage3")

	// Create blockchains with initial accounts
	accounts := []string{
		suite.wallet1.GetAddress().Hex(),
		suite.wallet2.GetAddress().Hex(),
		suite.wallet3.GetAddress().Hex(),
	}
	amounts := []uint64{1000, 1000, 1000}
	stakeAmounts := []uint64{4000, 2000, 0}
	thresholdStake := uint64(400)

	suite.chain1 = blockchain.NewBlockchain(storage1, accounts, amounts, stakeAmounts, thresholdStake, suite.stakeAddress)
	suite.chain2 = blockchain.NewBlockchain(storage2, accounts, amounts, stakeAmounts, thresholdStake, suite.stakeAddress)
	suite.chain3 = blockchain.NewBlockchain(storage3, accounts, amounts, stakeAmounts, thresholdStake, suite.stakeAddress)

	// Create harbor servers
	suite.harborServer1 = NewHarborServer(suite.txPool1, suite.chain1, accounts[0], suite.logger)
	suite.harborServer2 = NewHarborServer(suite.txPool2, suite.chain2, accounts[1], suite.logger)
	suite.harborServer3 = NewHarborServer(suite.txPool3, suite.chain3, accounts[2], suite.logger)

	// Create execution clients with longer timeouts
	suite.client1, err = NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		suite.harborServer1,
		suite.logger,
	)
	suite.Require().NoError(err, "Failed to create client1")

	connection := suite.client1.IsConnectedTo(suite.client1.GetAddress())
	suite.False(connection)

	suite.client2, err = NewExecutionClient(
		listenAddr,
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		suite.harborServer2,
		suite.logger,
	)
	suite.Require().NoError(err, "Failed to create client2")

	suite.client3, err = NewExecutionClient(
		listenAddr,
		suite.txPool3,
		suite.chain3,
		suite.wallet3.GetAddress(),
		suite.harborServer3,
		suite.logger,
	)
	suite.Require().NoError(err, "Failed to create client3")

	// Create servers for clients
	server1 := NewServer(suite.client1)
	server2 := NewServer(suite.client2)
	server3 := NewServer(suite.client3)

	// Start clients with proper delays
	err = suite.client1.Start("5051", server1, "8081")
	suite.Require().NoError(err, "Failed to start client1")
	time.Sleep(500 * time.Millisecond) // Wait for client1 to fully initialize

	err = suite.client2.Start("5052", server2, "8082")
	suite.Require().NoError(err, "Failed to start client2")
	time.Sleep(500 * time.Millisecond) // Wait for client2 to fully initialize

	err = suite.client3.Start("5053", server3, "8083")
	suite.Require().NoError(err, "Failed to start client3")
	time.Sleep(500 * time.Millisecond) // Wait for client3 to fully initialize

	// Wait for peer discovery and connection with timeout
	timeout := time.After(20 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fmt.Println("here 00", len(suite.client1.GetPeers()), "&&",
				len(suite.client2.GetPeers()), "&&",
				len(suite.client3.GetPeers()))
			connected := len(suite.client1.GetPeers()) == 2 &&
				len(suite.client2.GetPeers()) == 2 &&
				len(suite.client3.GetPeers()) == 2
			if connected {
				fmt.Println("All peers connected successfully")
				return
			} else {
				suite.client1.ConnectToPeer(suite.client2.GetAddress())
				suite.client1.ConnectToPeer(suite.client3.GetAddress())
				suite.client2.ConnectToPeer(suite.client3.GetAddress())
			}
		case <-timeout:
			suite.Fail("Timeout waiting for peer connections")
			return
		}
	}
}

func (suite *ExecutionClientTestSuite) TearDownTest() {
	fmt.Println("\n ** Tearing down test environment...")

	// Stop clients in reverse order
	if suite.client3 != nil {
		suite.client3.Stop()
		time.Sleep(500 * time.Millisecond)
	}
	if suite.client2 != nil {
		suite.client2.Stop()
		time.Sleep(500 * time.Millisecond)
	}
	if suite.client1 != nil {
		suite.client1.Stop()
		time.Sleep(500 * time.Millisecond)
	}

	// Clean up storage
	if suite.chain1 != nil {
		suite.chain1.Storage.Close()
	}
	if suite.chain2 != nil {
		suite.chain2.Storage.Close()
	}
	if suite.chain3 != nil {
		suite.chain3.Storage.Close()
	}

	// Clean up test data directory
	os.RemoveAll("./testdata")
	// Give time for the clients to stop
	time.Sleep(1 * time.Second)
}

func TestExecutionClientTestSuite(t *testing.T) {
	suite.Run(t, new(ExecutionClientTestSuite))
}

func (suite *ExecutionClientTestSuite) TestTransactionPropagation() {
	fmt.Println("\nTesting transaction propagation between nodes...")

	// Ensure clients are initialized
	suite.Require().NotNil(suite.client1, "client1 should not be nil")
	suite.Require().NotNil(suite.client2, "client2 should not be nil")
	suite.Require().NotNil(suite.client3, "client3 should not be nil")

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

	// Wait for transaction to be processed with timeout
	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if transaction exists in all pools
			hasTx1 := suite.client1.txPool.HasTransaction(tx.TransactionHash)
			hasTx2 := suite.client2.txPool.HasTransaction(tx.TransactionHash)
			hasTx3 := suite.client3.txPool.HasTransaction(tx.TransactionHash)

			if hasTx1 && hasTx2 && hasTx3 {
				// Verify transaction details in all pools
				tx1, exists1 := suite.client1.txPool.GetTransaction(tx.TransactionHash)
				tx2, exists2 := suite.client2.txPool.GetTransaction(tx.TransactionHash)
				tx3, exists3 := suite.client3.txPool.GetTransaction(tx.TransactionHash)

				suite.True(exists1, "Transaction should exist in client1's pool")
				suite.True(exists2, "Transaction should exist in client2's pool")
				suite.True(exists3, "Transaction should exist in client3's pool")

				// Verify transaction details are consistent
				suite.Equal(tx1.Sender, tx.Sender, "Sender should match")
				suite.Equal(tx1.Receiver, tx.Receiver, "Receiver should match")
				suite.Equal(tx1.Amount, tx.Amount, "Amount should match")
				suite.Equal(tx1.Nonce, tx.Nonce, "Nonce should match")

				suite.Equal(tx2.Sender, tx.Sender, "Sender should match")
				suite.Equal(tx2.Receiver, tx.Receiver, "Receiver should match")
				suite.Equal(tx2.Amount, tx.Amount, "Amount should match")
				suite.Equal(tx2.Nonce, tx.Nonce, "Nonce should match")

				suite.Equal(tx3.Sender, tx.Sender, "Sender should match")
				suite.Equal(tx3.Receiver, tx.Receiver, "Receiver should match")
				suite.Equal(tx3.Amount, tx.Amount, "Amount should match")
				suite.Equal(tx3.Nonce, tx.Nonce, "Nonce should match")

				fmt.Println("Transaction successfully propagated to all nodes!")
				return
			}
		case <-timeout:
			suite.Fail("Timeout waiting for transaction propagation")
			return
		}
	}
}

func (suite *ExecutionClientTestSuite) TestNewExecutionClient() {
	// Test valid creation
	suite.Require().NotNil(suite.client1)
	suite.Require().NotNil(suite.client1.host)
	suite.Require().NotNil(suite.client1.pubsub)
	suite.Require().NotNil(suite.client1.transactionCh)
	suite.Require().NotNil(suite.client1.seenMessages)
	suite.Require().NotNil(suite.client1.connectCh)

	// Test nil transaction pool
	_, err := NewExecutionClient(
		listenAddr,
		nil,
		suite.chain1,
		suite.wallet1.GetAddress(),
		suite.harborServer1,
		suite.logger,
	)
	suite.Require().Error(err)

	// Test nil blockchain
	_, err = NewExecutionClient(
		listenAddr,
		suite.txPool1,
		nil,
		suite.wallet1.GetAddress(),
		suite.harborServer1,
		suite.logger,
	)
	suite.Require().Error(err)
}

func (suite *ExecutionClientTestSuite) TestConnectionStatus() {
	// Test connection status after connecting
	time.Sleep(1 * time.Second) // Give time for connection to establish
	suite.True(suite.client2.IsConnectedTo(suite.client1.GetAddress()))
}

func (suite *ExecutionClientTestSuite) TestInvalidPeerConnection() {
	// Test connecting to invalid peer address
	err := suite.client1.ConnectToPeer("invalid-address")
	suite.Require().Error(err)

	// Test connecting to non-existent peer
	err = suite.client1.ConnectToPeer("/ip4/127.0.0.1/tcp/5052/p2p/QmInvalidPeerID")
	suite.Require().Error(err)
}
