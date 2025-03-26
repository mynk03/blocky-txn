package transactions

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
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

	txn.TransactionHash = txn.GenerateHash()
	return txn
}

// Define the test suite
type TransactionPoolTestSuite struct {
	suite.Suite
	tp *TransactionPool
}

// Setup the test suite
func (suite *TransactionPoolTestSuite) SetupTest() {
	suite.tp = NewTransactionPool()
}

// Teardown the test suite
func (suite *TransactionPoolTestSuite) TearDownTest() {

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
}

func (suite *TransactionPoolTestSuite) TestAddInvalidTransaction() {
	txInvalid := Transaction{TransactionHash: "invalid"}
	err := suite.tp.AddTransaction(txInvalid)
	suite.Error(err)
	suite.NotContains(suite.tp.PendingTransactions, txInvalid)
}

func (suite *TransactionPoolTestSuite) TestRemoveTransaction() {
	// Create a test transaction
	tx := Transaction{
		From:        common.HexToAddress("0x123"),
		To:          common.HexToAddress("0x456"),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}
	tx.TransactionHash = tx.GenerateHash()

	// Test removing non-existent transaction
	err := suite.tp.RemoveTransaction("non_existent_hash")
	suite.Error(err)
	suite.Equal("transaction hash not found", err.Error())

	// Add transaction to pool
	suite.tp.PendingTransactions = append(suite.tp.PendingTransactions, tx)

	// Test removing existing transaction
	err = suite.tp.RemoveTransaction(tx.TransactionHash)
	suite.NoError(err)
	suite.Len(suite.tp.PendingTransactions, 0)

	// Test removing same transaction again
	err = suite.tp.RemoveTransaction(tx.TransactionHash)
	suite.Error(err)
	suite.Equal("transaction hash not found", err.Error())
}

func (suite *TransactionPoolTestSuite) TestRemoveBulkTransactions() {
	// Create test transactions
	txs := []Transaction{
		randomTransaction(),
		randomTransaction(),
	}

	// Generate hashes and add to pool
	for _, tx := range txs {
		tx.TransactionHash = tx.GenerateHash()
		suite.tp.PendingTransactions = append(suite.tp.PendingTransactions, tx)
	}

	// Test removing multiple transactions
	hashes := []string{
		txs[0].TransactionHash,
		txs[1].TransactionHash,
		"non_existent_hash", // This should be logged but not cause an error
	}

	// Capture log output
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)

	// Remove transactions
	suite.tp.RemoveBulkTransactions(hashes)

	// Verify transactions were removed
	suite.Len(suite.tp.PendingTransactions, 0)

	// Verify log output contains error for non-existent transaction
	logString := logBuffer.String()
	suite.Contains(logString, "failed to remove transaction")
	suite.Contains(logString, "non_existent_hash")
}

func (suite *TransactionPoolTestSuite) TestRemoveBulkTransactionsWithEmptyPool() {
	// Test removing transactions from empty pool
	hashes := []string{"hash1", "hash2"}
	suite.tp.RemoveBulkTransactions(hashes)
	suite.Len(suite.tp.PendingTransactions, 0)
}

func (suite *TransactionPoolTestSuite) TestRemoveBulkTransactionsWithPartialSuccess() {
	// Create test transactions
	tx := Transaction{
		From:        common.HexToAddress("0x123"),
		To:          common.HexToAddress("0x456"),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}
	tx.TransactionHash = tx.GenerateHash()
	suite.tp.PendingTransactions = append(suite.tp.PendingTransactions, tx)

	// Test removing mix of existing and non-existing transactions
	hashes := []string{
		tx.TransactionHash,
		"non_existent_hash",
	}

	// Capture log output
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)

	// Remove transactions
	suite.tp.RemoveBulkTransactions(hashes)

	// Verify existing transaction was removed
	suite.Len(suite.tp.PendingTransactions, 0)

	// Verify log output contains error for non-existent transaction
	logString := logBuffer.String()
	suite.Contains(logString, "failed to remove transaction")
	suite.Contains(logString, "non_existent_hash")
}

func (suite *TransactionPoolTestSuite) TestGetPendingTransactions() {
	suite.Equal(0, len(suite.tp.GetPendingTransactions()))
}

func (suite *TransactionPoolTestSuite) TestGetTransactionByHash() {
	tx1 := randomTransaction()
	suite.tp.AddTransaction(tx1)
	foundTx := suite.tp.GetTransactionByHash(tx1.TransactionHash)

	suite.NotNil(foundTx)
	suite.Equal(tx1.GenerateHash(), foundTx.TransactionHash)
	suite.Equal(tx1.From, foundTx.From)
	suite.Equal(tx1.To, foundTx.To)
	suite.Equal(tx1.Amount, foundTx.Amount)
	suite.Equal(tx1.Nonce, foundTx.Nonce)
}

func (suite *TransactionPoolTestSuite) TestGetTransactionByHashNonExistent() {
	foundTx := suite.tp.GetTransactionByHash(randomTransaction().TransactionHash)
	suite.Nil(foundTx)
}

// Test related to the transaction.go
