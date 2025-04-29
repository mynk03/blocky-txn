package execution

import (
	"blockchain-simulator/internal/blockchain"
	"blockchain-simulator/internal/transaction"
	"blockchain-simulator/internal/wallet"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type EnhancedExecutionClientTestSuite struct {
	suite.Suite
	client1       *ExecutionClient
	client2       *ExecutionClient
	txPool1       *transaction.TransactionPool
	txPool2       *transaction.TransactionPool
	chain1        *blockchain.Blockchain
	chain2        *blockchain.Blockchain
	wallet1       *wallet.MockWallet
	wallet2       *wallet.MockWallet
	harborServer1 *HarborServer
	harborServer2 *HarborServer
	testDataDir   string
	logger        *logrus.Logger
	ctx           context.Context
	cancel        context.CancelFunc
}

func (suite *EnhancedExecutionClientTestSuite) SetupSuite() {
	suite.ctx, suite.cancel = context.WithCancel(context.Background())
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.DebugLevel)

	// Create test data directory
	suite.testDataDir = "./testdata"
	err := os.MkdirAll(suite.testDataDir, 0755)
	suite.Require().NoError(err)

	// Create validator wallets
	suite.wallet1, err = wallet.NewMockWallet()
	suite.Require().NoError(err)
	suite.wallet2, err = wallet.NewMockWallet()
	suite.Require().NoError(err)

	// Create transaction pools
	suite.txPool1 = transaction.NewTransactionPool()
	suite.txPool2 = transaction.NewTransactionPool()

	// Create storage for blockchains
	storage1, err := blockchain.NewLevelDBStorage(filepath.Join(suite.testDataDir, "node1"))
	suite.Require().NoError(err)
	storage2, err := blockchain.NewLevelDBStorage(filepath.Join(suite.testDataDir, "node2"))
	suite.Require().NoError(err)

	// Create blockchains with initial accounts
	accounts1 := []string{suite.wallet1.GetAddress().Hex()}
	accounts2 := []string{suite.wallet2.GetAddress().Hex()}
	amounts := []uint64{1000}

	suite.chain1 = blockchain.NewBlockchain(storage1, accounts1, amounts)
	suite.chain2 = blockchain.NewBlockchain(storage2, accounts2, amounts)

	// Create harbor servers
	suite.harborServer1 = NewHarborServer(suite.txPool1, suite.chain1, accounts1[0], suite.logger)
	suite.harborServer2 = NewHarborServer(suite.txPool2, suite.chain2, accounts2[0], suite.logger)
}

func (suite *EnhancedExecutionClientTestSuite) TearDownSuite() {
	// Cancel context to stop all goroutines
	suite.cancel()

	// Clean up storage
	if suite.chain1 != nil {
		suite.chain1.Storage.Close()
	}
	if suite.chain2 != nil {
		suite.chain2.Storage.Close()
	}

	// Clean up test data directory
	os.RemoveAll(suite.testDataDir)
}

func (suite *EnhancedExecutionClientTestSuite) SetupTest() {
	var err error

	// Create execution clients
	suite.client1, err = NewExecutionClient(
		"/ip4/127.0.0.1/tcp/5051",
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		suite.harborServer1,
		suite.logger,
	)
	suite.Require().NoError(err)

	suite.client2, err = NewExecutionClient(
		"/ip4/127.0.0.1/tcp/5052",
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		suite.harborServer2,
		suite.logger,
	)
	suite.Require().NoError(err)
}

func (suite *EnhancedExecutionClientTestSuite) TearDownTest() {
	if suite.client1 != nil {
		suite.client1.Stop()
	}
	if suite.client2 != nil {
		suite.client2.Stop()
	}
}

func TestEnhancedExecutionClientSuite(t *testing.T) {
	suite.Run(t, new(EnhancedExecutionClientTestSuite))
}

func (suite *EnhancedExecutionClientTestSuite) TestNewExecutionClient() {
	// Test valid creation
	suite.Require().NotNil(suite.client1)
	suite.Require().NotNil(suite.client1.host)
	suite.Require().NotNil(suite.client1.pubsub)
	suite.Require().NotNil(suite.client1.transactionCh)
	suite.Require().NotNil(suite.client1.seenMessages)
	suite.Require().NotNil(suite.client1.connectCh)

	// Test nil transaction pool
	_, err := NewExecutionClient(
		"/ip4/127.0.0.1/tcp/5051",
		nil,
		suite.chain1,
		suite.wallet1.GetAddress(),
		suite.harborServer1,
		suite.logger,
	)
	suite.Require().Error(err)

	// Test nil blockchain
	_, err = NewExecutionClient(
		"/ip4/127.0.0.1/tcp/5051",
		suite.txPool1,
		nil,
		suite.wallet1.GetAddress(),
		suite.harborServer1,
		suite.logger,
	)
	suite.Require().Error(err)
}

func (suite *EnhancedExecutionClientTestSuite) TestPeerDiscovery() {
	// Create servers
	server1 := NewServer(suite.client1)
	server2 := NewServer(suite.client2)

	// Start both clients
	err := suite.client1.Start("5051", server1, "8081")
	suite.Require().NoError(err)

	err = suite.client2.Start("5052", server2, "8082")
	suite.Require().NoError(err)

	// Wait for servers to start
	time.Sleep(100 * time.Millisecond)

	// Test peer discovery
	client1Addr := suite.client1.GetAddress()
	err = suite.client2.ConnectToPeer(client1Addr)
	suite.Require().NoError(err)

	// Verify connection
	time.Sleep(1 * time.Second) // Give time for connection to establish
	suite.True(suite.client2.IsConnectedTo(client1Addr))

	// Test GetPeers
	peers := suite.client2.GetPeers()
	suite.Len(peers, 1)
	suite.Contains(peers, client1Addr)
}

func (suite *EnhancedExecutionClientTestSuite) TestBroadcastTransaction() {
	// Create servers
	server1 := NewServer(suite.client1)
	server2 := NewServer(suite.client2)

	// Start both clients
	err := suite.client1.Start("5051", server1, "8081")
	suite.Require().NoError(err)

	err = suite.client2.Start("5052", server2, "8082")
	suite.Require().NoError(err)

	// Wait for servers to start
	time.Sleep(100 * time.Millisecond)

	// Connect clients
	client1Addr := suite.client1.GetAddress()
	err = suite.client2.ConnectToPeer(client1Addr)
	suite.Require().NoError(err)

	// Wait for connection to establish
	time.Sleep(1 * time.Second)

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

	err = suite.client1.BroadcastTransaction(tx)
	suite.Require().NoError(err)

	// Wait for transaction propagation
	time.Sleep(1 * time.Second)

	// Verify transaction was received by both clients
	suite.True(suite.txPool1.HasTransaction(tx.TransactionHash))
	suite.True(suite.txPool2.HasTransaction(tx.TransactionHash))
}

func (suite *EnhancedExecutionClientTestSuite) TestConnectionStatus() {
	// Create servers
	server1 := NewServer(suite.client1)
	server2 := NewServer(suite.client2)

	// Start both clients
	err := suite.client1.Start("5051", server1, "8081")
	suite.Require().NoError(err)

	err = suite.client2.Start("5052", server2, "8082")
	suite.Require().NoError(err)

	// Wait for servers to start
	time.Sleep(100 * time.Millisecond)

	// Test connection status before connecting
	client1Addr := suite.client1.GetAddress()
	suite.False(suite.client2.IsConnectedTo(client1Addr))

	// Connect clients
	err = suite.client2.ConnectToPeer(client1Addr)
	suite.Require().NoError(err)

	// Test connection status after connecting
	time.Sleep(1 * time.Second) // Give time for connection to establish
	suite.True(suite.client2.IsConnectedTo(client1Addr))
}

func (suite *EnhancedExecutionClientTestSuite) TestInvalidPeerConnection() {
	// Test connecting to invalid peer address
	err := suite.client1.ConnectToPeer("invalid-address")
	suite.Require().Error(err)

	// Test connecting to non-existent peer
	err = suite.client1.ConnectToPeer("/ip4/127.0.0.1/tcp/5052/p2p/QmInvalidPeerID")
	suite.Require().Error(err)
}
