package transactions

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

const (
	user1 = "0x100000100000000000000000000000000000000a"
	user2 = "0x100000100000000000000000000000000000000d"
)

var currentNonce uint64 = 1
var blockNumber uint32 = 1

func randomTransaction() Transaction {
	amount := uint64(rand.Intn(1000))
	nonce := currentNonce
	currentNonce++
	txn := Transaction{
		TransactionHash: "", // populate later
		From:            common.HexToAddress(user1),
		To:              common.HexToAddress(user2),
		BlockNumber:     blockNumber,
		Timestamp:       uint64(time.Now().Second()),
		Status:          1,
		Amount:          amount,
		Nonce:           nonce,
	}

	txn.TransactionHash = txn.Hash()
	return txn
}

// Define the test suite
type TransactionPoolTestSuite struct {
	suite.Suite
	tp      *TransactionPool
	storage *LevelDBStorage
}

// Setup the test suite
func (suite *TransactionPoolTestSuite) SetupTest() {
	suite.storage = InitializeStorage("test_pool_data")
	suite.tp, _ = NewTransactionPool(suite.storage)
}

// Teardown the test suite
func (suite *TransactionPoolTestSuite) TearDownTest() {
	if suite.storage != nil {
		suite.storage.db.Close() // Ensure the database is closed
	}
	os.RemoveAll("test_pool_data")
}

// Run the test suite
func TestTransactionPoolTestSuite(t *testing.T) {
	suite.Run(t, new(TransactionPoolTestSuite))
}

// Test methods
func (suite *TransactionPoolTestSuite) TestAddTransaction() {
	tx1 := randomTransaction()
	err := suite.tp.AddTransaction(tx1)
	suite.NoError(err)
	suite.Contains(suite.tp.PendingTransactions, tx1)
	suite.Contains(suite.tp.AllTransactions, tx1)
}

func (suite *TransactionPoolTestSuite) TestAddInvalidTransaction() {
	txInvalid := Transaction{TransactionHash: "invalid"}
	err := suite.tp.AddTransaction(txInvalid)
	suite.Error(err)
	suite.NotContains(suite.tp.PendingTransactions, txInvalid)
}

func (suite *TransactionPoolTestSuite) TestRemoveTransaction() {
	tx1 := randomTransaction()
	suite.tp.AddTransaction(tx1)
	err := suite.tp.RemoveTransaction(tx1.TransactionHash)
	suite.NoError(err)
	suite.NotContains(suite.tp.PendingTransactions, tx1)
}

func (suite *TransactionPoolTestSuite) TestRemoveBulkTransactions() {
	tx2 := randomTransaction()
	tx3 := randomTransaction()

	suite.tp.AddTransaction(tx2)
	suite.tp.RemoveBulkTransactions([]string{tx2.Hash(), tx3.Hash()})
	suite.NotContains(suite.tp.PendingTransactions, tx2)
	suite.NotContains(suite.tp.PendingTransactions, tx3)
}

func (suite *TransactionPoolTestSuite) TestGetPendingTransactions() {
	suite.Equal(0, len(suite.tp.GetPendingTransactions()))
}

func (suite *TransactionPoolTestSuite) TestGetAllTransactions() {
	tx1 := randomTransaction()
	suite.tp.AddTransaction(tx1)
	suite.Equal(1, len(suite.tp.GetAllTransactions())) // Only tx1 should be in AllTransactions
}

func (suite *TransactionPoolTestSuite) TestGetTransactionByHash() {
	tx1 := randomTransaction()
	suite.tp.AddTransaction(tx1)
	foundTx := suite.tp.GetTransactionByHash(tx1.TransactionHash)

	suite.NotNil(foundTx)
	suite.Equal(tx1.Hash(), foundTx.TransactionHash)
	suite.Equal(tx1.From, foundTx.From)
	suite.Equal(tx1.To, foundTx.To)
	suite.Equal(tx1.Amount, foundTx.Amount)
	suite.Equal(tx1.Nonce, foundTx.Nonce)
}

func (suite *TransactionPoolTestSuite) TestGetTransactionByHashNonExistent() {
	foundTx := suite.tp.GetTransactionByHash(randomTransaction().TransactionHash)
	suite.Nil(foundTx)
}
