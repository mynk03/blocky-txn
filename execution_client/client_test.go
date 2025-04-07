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

	// Create two execution clients
	suite.client1, err = NewExecutionClient(
		"/ip4/127.0.0.1/tcp/0",
		suite.txPool1,
		suite.chain1,
		suite.wallet1.GetAddress(),
		nil,
	)
	suite.Require().NoError(err, "Failed to create client1")

	suite.client2, err = NewExecutionClient(
		"/ip4/127.0.0.1/tcp/0",
		suite.txPool2,
		suite.chain2,
		suite.wallet2.GetAddress(),
		nil,
	)
	suite.Require().NoError(err, "Failed to create client2")

	// Start both clients
	err = suite.client1.Start()
	suite.Require().NoError(err, "Failed to start client1")
	err = suite.client2.Start()
	suite.Require().NoError(err, "Failed to start client2")
}

func (suite *ExecutionClientTestSuite) TearDownTest() {
	// Stop clients
	if suite.client1 != nil {
		suite.client1.Stop()
	}
	if suite.client2 != nil {
		suite.client2.Stop()
	}

	// Clean up storage
	if suite.chain1 != nil {
		suite.chain1.Storage.Close()
	}
	if suite.chain2 != nil {
		suite.chain2.Storage.Close()
	}

	// Clean up test data directory
	os.RemoveAll("./testdata")
}

func (suite *ExecutionClientTestSuite) TestTransactionPropagation() {
	fmt.Println("\nTesting transaction propagation between two nodes...")

	// Connect client2 to client1
	addr1 := suite.client1.GetAddress()
	err := suite.client2.ConnectToPeer(addr1)
	suite.Require().NoError(err, "Failed to connect client2 to client1")

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	// Create a simple transaction
	tx := transaction.NewTransaction(
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
		common.HexToAddress("0x0987654321098765432109876543210987654321"),
		100,
		0,
	)

	// Broadcast transaction from client1
	fmt.Printf("Broadcasting transaction from client1 (hash: %s)\n", tx.TransactionHash)
	err = suite.client1.BroadcastTransaction(*tx)
	suite.Require().NoError(err, "Failed to broadcast transaction")

	// Wait for transaction to be processed
	time.Sleep(100 * time.Millisecond)

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

func TestExecutionClientSuite(t *testing.T) {
	suite.Run(t, new(ExecutionClientTestSuite))
}
