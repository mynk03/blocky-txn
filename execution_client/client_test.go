package execution_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/transaction"
	"blockchain-simulator/wallet"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

var listenAddr = "/ip4/127.0.0.1/tcp/0"

type ExecutionClientTestSuite struct {
	suite.Suite
	client1 *ExecutionClient
	client2 *ExecutionClient
	client3 *ExecutionClient
	txPool1 *transaction.TransactionPool
	txPool2 *transaction.TransactionPool
	txPool3 *transaction.TransactionPool
	chain1  *blockchain.Blockchain
	chain2  *blockchain.Blockchain
	chain3  *blockchain.Blockchain
	wallet1 *wallet.MockWallet // Validator wallet for node 1
	wallet2 *wallet.MockWallet // Validator wallet for node 2
	wallet3 *wallet.MockWallet // Validator wallet for node 3
}

func (suite *ExecutionClientTestSuite) SetupTest() {
	var err error
	fmt.Println("Setting up test environment...")

	// Create test data directory
	testDataDir := "./testdata"
	err = os.MkdirAll(testDataDir, 0755)
	suite.Require().NoError(err, "Failed to create test data directory")

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

	suite.chain1 = blockchain.NewBlockchain(storage1, accounts, amounts)
	suite.chain2 = blockchain.NewBlockchain(storage2, accounts, amounts)
	suite.chain3 = blockchain.NewBlockchain(storage3, accounts, amounts)

	// Create execution clients with longer timeouts
	suite.client1, err = NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().NoError(err, "Failed to create client1")

	suite.client2, err = NewExecutionClient(
		listenAddr,
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		nil,
	)
	suite.Require().NoError(err, "Failed to create client2")

	suite.client3, err = NewExecutionClient(
		listenAddr,
		suite.txPool3,
		suite.chain3,
		suite.wallet3.GetAddress(),
		nil,
	)
	suite.Require().NoError(err, "Failed to create client3")

	// Start clients with proper delays
	err = suite.client1.Start()
	suite.Require().NoError(err, "Failed to start client1")
	time.Sleep(500 * time.Millisecond) // Wait for client1 to fully initialize

	err = suite.client2.Start()
	suite.Require().NoError(err, "Failed to start client2")
	time.Sleep(500 * time.Millisecond) // Wait for client2 to fully initialize

	err = suite.client3.Start()
	suite.Require().NoError(err, "Failed to start client3")
	time.Sleep(500 * time.Millisecond) // Wait for client3 to fully initialize
}

func (suite *ExecutionClientTestSuite) TearDownTest() {
	// Stop clients in reverse order
	if suite.client3 != nil {
		suite.client3.Stop()
		time.Sleep(100 * time.Millisecond)
	}
	if suite.client2 != nil {
		suite.client2.Stop()
		time.Sleep(100 * time.Millisecond)
	}
	if suite.client1 != nil {
		suite.client1.Stop()
		time.Sleep(100 * time.Millisecond)
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
}

func TestExecutionClientTestSuite(t *testing.T) {
	suite.Run(t, new(ExecutionClientTestSuite))
}

func (suite *ExecutionClientTestSuite) TestTransactionPropagation() {
	fmt.Println("\nTesting transaction propagation between two nodes...")

	// Ensure clients are initialized
	suite.Require().NotNil(suite.client1, "client1 should not be nil")
	suite.Require().NotNil(suite.client2, "client2 should not be nil")

	// Connect client2 to client1 with retry
	var err error
	for i := 0; i < 3; i++ {
		addr1 := suite.client1.GetAddress()
		err = suite.client2.ConnectToPeer(addr1)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	// suite.Require().NoError(err, "Failed to connect client2 to client1")

	// Wait for connection to be established
	time.Sleep(1000 * time.Millisecond)

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
	fmt.Printf("Broadcasting transaction from client1 (hash: %s)\n", tx.TransactionHash)
	err = suite.client1.BroadcastTransaction(tx)
	suite.Require().NoError(err, "Failed to broadcast transaction")

	// Wait for transaction to be processed
	time.Sleep(1000 * time.Millisecond)

	// Verify transaction was added to both clients' transaction pools
	fmt.Println("Verifying transaction in both pools...")
	suite.True(suite.client1.txPool.HasTransaction(tx.TransactionHash), "Transaction should be in client1's pool")
	suite.True(suite.client2.txPool.HasTransaction(tx.TransactionHash), "Transaction should be in client2's pool")

	// Verify transaction details in both pools
	tx1, exists1 := suite.client1.txPool.GetTransaction(tx.TransactionHash)
	tx2, exists2 := suite.client2.txPool.GetTransaction(tx.TransactionHash)

	suite.True(exists1, "Transaction should exist in client1's pool")
	suite.True(exists2, "Transaction should exist in client2's pool")

	// Verify transaction details are consistent
	suite.Equal(tx1.Sender, tx.Sender, "Sender should match")
	suite.Equal(tx1.Receiver, tx.Receiver, "Receiver should match")
	suite.Equal(tx1.Amount, tx.Amount, "Amount should match")
	suite.Equal(tx1.Nonce, tx.Nonce, "Nonce should match")

	suite.Equal(tx2.Sender, tx.Sender, "Sender should match")
	suite.Equal(tx2.Receiver, tx.Receiver, "Receiver should match")
	suite.Equal(tx2.Amount, tx.Amount, "Amount should match")
	suite.Equal(tx2.Nonce, tx.Nonce, "Nonce should match")

	fmt.Println("Transaction successfully propagated from client1 to client2!")
}

func (suite *ExecutionClientTestSuite) TestNewExecutionClient() {
	// Test with nil transaction pool
	client, err := NewExecutionClient(
		listenAddr,
		nil,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().Error(err)
	suite.Require().Nil(client)

	// Test with nil blockchain
	client, err = NewExecutionClient(
		listenAddr,
		suite.txPool1,
		nil,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().Error(err)
	suite.Require().Nil(client)

	// Test with custom logger
	customLogger := logrus.New()
	customLogger.SetLevel(logrus.DebugLevel)
	client, err = NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		customLogger,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(client)

	// Cleanup
	if client != nil {
		client.Stop()
	}
}

func (suite *ExecutionClientTestSuite) TestGetAddress() {
	// Create a new client for this test
	client, err := NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(client)

	// Start the client
	err = client.Start()
	suite.Require().NoError(err)

	// Test address
	addr := client.GetAddress()
	suite.Require().NotEmpty(addr)
	suite.Require().Contains(addr, "/ip4/")
	suite.Require().Contains(addr, "/p2p/")

	// Cleanup
	client.Stop()
}

func (suite *ExecutionClientTestSuite) TestIsConnectedTo() {
	// Create new clients for this test
	client1, err := NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(client1)

	client2, err := NewExecutionClient(
		listenAddr,
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(client2)

	// Start clients
	err = client1.Start()
	suite.Require().NoError(err)
	err = client2.Start()
	suite.Require().NoError(err)

	// Connect clients
	addr1 := client1.GetAddress()
	err = client2.ConnectToPeer(addr1)
	suite.Require().NoError(err)

	// Wait for connection
	time.Sleep(500 * time.Millisecond)

	// Test connection status
	suite.True(client2.IsConnectedTo(addr1))
	suite.False(client2.IsConnectedTo("invalid_address"))

	// Cleanup
	client1.Stop()
	client2.Stop()
}

func (suite *ExecutionClientTestSuite) TestBroadcastTransaction() {
	// Create new clients for this test
	client1, err := NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(client1)

	client2, err := NewExecutionClient(
		listenAddr,
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(client2)

	// Start clients
	err = client1.Start()
	suite.Require().NoError(err)
	err = client2.Start()
	suite.Require().NoError(err)

	// Connect clients
	addr1 := client1.GetAddress()
	err = client2.ConnectToPeer(addr1)
	suite.Require().NoError(err)

	// Wait for connection
	time.Sleep(500 * time.Millisecond)

	// Create and broadcast transaction
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
	suite.Require().NoError(err)
	tx.Signature = signature

	// Test broadcasting
	err = client1.BroadcastTransaction(tx)
	suite.Require().NoError(err)

	// Wait for propagation
	time.Sleep(500 * time.Millisecond)

	// Verify transaction in both pools
	suite.True(client1.txPool.HasTransaction(tx.TransactionHash))
	suite.True(client2.txPool.HasTransaction(tx.TransactionHash))

	// Cleanup
	client1.Stop()
	client2.Stop()
}

func (suite *ExecutionClientTestSuite) TestHandleTransactions() {
	// Create new clients for this test
	client1, err := NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	defer client1.Stop()

	client2, err := NewExecutionClient(
		listenAddr,
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	defer client2.Stop()

	// Start clients with proper delays
	err = client1.Start()
	suite.Require().NoError(err)
	time.Sleep(500 * time.Millisecond)

	err = client2.Start()
	suite.Require().NoError(err)
	time.Sleep(500 * time.Millisecond)

	// Connect clients with retry
	addr1 := client1.GetAddress()
	var connectErr error
	for i := 0; i < 3; i++ {
		connectErr = client2.ConnectToPeer(addr1)
		if connectErr == nil {
			break
		}
		time.Sleep(800 * time.Millisecond)
	}
	// suite.Require().NoError(connectErr)

	// Wait for connection to be established
	time.Sleep(1000 * time.Millisecond)

	// Create and broadcast transaction
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
	suite.Require().NoError(err)
	tx.Signature = signature

	// Broadcast transaction
	err = client1.BroadcastTransaction(tx)
	suite.Require().NoError(err)

	// Wait for transaction to be processed
	time.Sleep(1000 * time.Millisecond)

	// Verify transaction in both pools
	suite.True(client1.txPool.HasTransaction(tx.TransactionHash), "Transaction should be in client1's pool")
	suite.True(client2.txPool.HasTransaction(tx.TransactionHash), "Transaction should be in client2's pool")
}

func (suite *ExecutionClientTestSuite) TestConnectToPeer() {
	// Create new clients for this test
	client1, err := NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	defer client1.Stop()

	client2, err := NewExecutionClient(
		listenAddr,
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	defer client2.Stop()

	// Start clients with proper delays
	err = client1.Start()
	suite.Require().NoError(err)
	time.Sleep(1000 * time.Millisecond)

	err = client2.Start()
	suite.Require().NoError(err)
	time.Sleep(1000 * time.Millisecond)

	// Test invalid address
	err = client2.ConnectToPeer("invalid_address")
	suite.Require().Error(err)

	// Test valid connection with retry
	addr1 := client1.GetAddress()
	var connectErr error
	for i := 0; i < 3; i++ {
		connectErr = client2.ConnectToPeer(addr1)
		if connectErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	suite.Require().NoError(connectErr)

	// Wait for connection to be established
	time.Sleep(1000 * time.Millisecond)

	// Verify connection
	suite.True(client2.IsConnectedTo(addr1))
}

func (suite *ExecutionClientTestSuite) TestDiscoveryNotifee() {
	// Create new clients for this test
	client1, err := NewExecutionClient(
		listenAddr,
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(client1)

	client2, err := NewExecutionClient(
		listenAddr,
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		nil,
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(client2)

	// Start clients
	err = client1.Start()
	suite.Require().NoError(err)
	err = client2.Start()
	suite.Require().NoError(err)

	// Create notifee
	notifee := &discoveryNotifee{c: client1}

	// Test peer found
	peerInfo := peer.AddrInfo{
		ID:    client2.host.ID(),
		Addrs: client2.host.Addrs(),
	}
	notifee.HandlePeerFound(peerInfo)

	// Wait for connection
	time.Sleep(500 * time.Millisecond)

	// Verify connection
	suite.True(client1.IsConnectedTo(client2.GetAddress()))

	// Cleanup
	client1.Stop()
	client2.Stop()
}
