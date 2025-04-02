package transaction

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"blockchain-simulator/state"
	"blockchain-simulator/wallet"

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

type TransactionPoolTestSuite struct {
	suite.Suite
	tp          *TransactionPool
	user1Wallet *wallet.MockWallet
	user2Wallet *wallet.MockWallet
	user3Wallet *wallet.MockWallet
	otherWallet *wallet.MockWallet
}

func (suite *TransactionPoolTestSuite) SetupTest() {
	suite.tp = NewTransactionPool()

	// Create wallets for testing
	var err error

	// Create user1 wallet
	suite.user1Wallet, err = wallet.NewMockWallet()
	suite.NoError(err)

	// Create user2 wallet
	suite.user2Wallet, err = wallet.NewMockWallet()
	suite.NoError(err)

	// Create user3 wallet
	suite.user3Wallet, err = wallet.NewMockWallet()
	suite.NoError(err)

	// Create other wallet for invalid cases
	suite.otherWallet, err = wallet.NewMockWallet()
	suite.NoError(err)
}

// Helper function to create and sign a transaction
func (suite *TransactionPoolTestSuite) createSignedTransaction(wallet *wallet.MockWallet, to common.Address, amount uint64, nonce uint64, blockNumber uint32) Transaction {
	tx := Transaction{
		From:        wallet.GetAddress(),
		To:          to,
		Amount:      amount,
		Nonce:       nonce,
		BlockNumber: blockNumber,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	// Sign the transaction
	txHash := common.HexToHash(tx.TransactionHash)
	signature, err := wallet.SignTransaction(txHash)
	suite.NoError(err)
	tx.Signature = signature

	return tx
}

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
	suite.Contains(suite.tp.GetAllTransactions(), tx1)
}

func (suite *TransactionPoolTestSuite) TestAddInvalidTransaction() {
	txInvalid := Transaction{TransactionHash: "invalid"}
	err := suite.tp.AddTransaction(txInvalid)
	suite.Error(err)
	suite.NotContains(suite.tp.GetAllTransactions(), txInvalid)
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
	suite.Equal("transaction not found", err.Error())

	// Add transaction to pool
	err = suite.tp.AddTransaction(tx)
	suite.NoError(err)

	// Test removing existing transaction
	err = suite.tp.RemoveTransaction(tx.TransactionHash)
	suite.NoError(err)
	suite.Len(suite.tp.GetAllTransactions(), 0)

	// Test removing same transaction again
	err = suite.tp.RemoveTransaction(tx.TransactionHash)
	suite.Error(err)
	suite.Equal("transaction not found", err.Error())
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
		err := suite.tp.AddTransaction(tx)
		suite.NoError(err)
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
	suite.Len(suite.tp.GetAllTransactions(), 0)

	// Verify log output contains error for non-existent transaction
	logString := logBuffer.String()
	suite.Contains(logString, "failed to remove transaction")
	suite.Contains(logString, "non_existent_hash")
}

func (suite *TransactionPoolTestSuite) TestRemoveBulkTransactionsWithEmptyPool() {
	// Test removing transactions from empty pool
	hashes := []string{"hash1", "hash2"}
	suite.tp.RemoveBulkTransactions(hashes)
	suite.Len(suite.tp.GetAllTransactions(), 0)
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
	err := suite.tp.AddTransaction(tx)
	suite.NoError(err)

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
	suite.Len(suite.tp.GetAllTransactions(), 0)

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

func (suite *TransactionPoolTestSuite) TestTransactionValidation() {
	// Test valid transaction
	tx := Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}
	tx.TransactionHash = tx.GenerateHash()
	valid, err := tx.Validate()
	suite.True(valid)
	suite.NoError(err)

	// Test transaction with empty sender
	txEmptyFrom := tx
	txEmptyFrom.From = common.Address{}
	txEmptyFrom.TransactionHash = txEmptyFrom.GenerateHash()
	valid, err = txEmptyFrom.Validate()
	suite.False(valid)
	suite.Equal(ErrInvalidSender, err)

	// Test transaction with empty recipient
	txEmptyTo := tx
	txEmptyTo.To = common.Address{}
	txEmptyTo.TransactionHash = txEmptyTo.GenerateHash()
	valid, err = txEmptyTo.Validate()
	suite.False(valid)
	suite.Equal(ErrInvalidRecipient, err)

	// Test transaction with zero amount
	txZeroAmount := tx
	txZeroAmount.Amount = 0
	txZeroAmount.TransactionHash = txZeroAmount.GenerateHash()
	valid, err = txZeroAmount.Validate()
	suite.False(valid)
	suite.Equal(ErrInvalidAmount, err)
}

func (suite *TransactionPoolTestSuite) TestTransactionStatus() {
	// Test all transaction status values
	suite.Equal(TransactionStatus(0), Success)
	suite.Equal(TransactionStatus(1), Pending)
	suite.Equal(TransactionStatus(2), Failed)

	// Test transaction with different statuses
	tx := randomTransaction()

	// Test Success status
	tx.Status = Success
	suite.Equal(Success, tx.Status)

	// Test Pending status
	tx.Status = Pending
	suite.Equal(Pending, tx.Status)

	// Test Failed status
	tx.Status = Failed
	suite.Equal(Failed, tx.Status)
}

func (suite *TransactionPoolTestSuite) TestTransactionHashGeneration() {
	tx := Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}

	// Generate hash
	hash1 := tx.GenerateHash()
	suite.NotEmpty(hash1)

	// Generate hash again - should be the same
	hash2 := tx.GenerateHash()
	suite.Equal(hash1, hash2)

	// Modify transaction and generate new hash - should be different
	tx.Amount = 200
	hash3 := tx.GenerateHash()
	suite.NotEqual(hash1, hash3)
}

func (suite *TransactionPoolTestSuite) TestValidateWithState() {
	// Create a test state trie
	stateTrie := state.NewMptTrie()

	// Create a test account with sufficient balance
	account := state.Account{
		Balance: 1000,
		Nonce:   1,
	}
	err := stateTrie.PutAccount(suite.user1Wallet.GetAddress(), &account)
	suite.NoError(err)

	// Create a valid transaction
	tx := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		100,
		1,
		1,
	)

	// Test valid transaction with state
	valid, err := tx.ValidateWithState(stateTrie)
	suite.True(valid)
	suite.NoError(err)

	// Test transaction with insufficient funds
	txInsufficient := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		2000,
		1,
		1,
	)
	valid, err = txInsufficient.ValidateWithState(stateTrie)
	suite.False(valid)
	suite.Equal(ErrInsufficientFunds, err)

	// Test transaction with invalid nonce
	txInvalidNonce := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		100,
		2,
		1,
	)
	valid, err = txInvalidNonce.ValidateWithState(stateTrie)
	suite.False(valid)
	suite.Equal(ErrInvalidNonce, err)

	// Test transaction with non-existent sender
	txInvalidSender := suite.createSignedTransaction(
		suite.otherWallet,
		suite.user2Wallet.GetAddress(),
		100,
		1,
		1,
	)
	valid, err = txInvalidSender.ValidateWithState(stateTrie)
	suite.False(valid)
	suite.Equal(ErrInvalidSender, err)
}

func (suite *TransactionPoolTestSuite) TestTransactionValidationWithState() {
	// Create a test state trie
	stateTrie := state.NewMptTrie()

	// Create test accounts
	account1 := state.Account{
		Balance: 1000,
		Nonce:   1,
	}
	account2 := state.Account{
		Balance: 500,
		Nonce:   1,
	}
	err := stateTrie.PutAccount(suite.user1Wallet.GetAddress(), &account1)
	suite.NoError(err)
	err = stateTrie.PutAccount(suite.user2Wallet.GetAddress(), &account2)
	suite.NoError(err)

	// Test multiple transactions in sequence
	tx1 := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		100,
		1,
		1,
	)

	tx2 := suite.createSignedTransaction(
		suite.user2Wallet,
		suite.user1Wallet.GetAddress(),
		50,
		1,
		1,
	)

	// Validate first transaction
	valid, err := tx1.ValidateWithState(stateTrie)
	suite.True(valid)
	suite.NoError(err)

	// Update state after first transaction
	account1.Balance -= tx1.Amount
	account2.Balance += tx1.Amount
	account1.Nonce++
	err = stateTrie.PutAccount(suite.user1Wallet.GetAddress(), &account1)
	suite.NoError(err)
	err = stateTrie.PutAccount(suite.user2Wallet.GetAddress(), &account2)
	suite.NoError(err)

	// Validate second transaction
	valid, err = tx2.ValidateWithState(stateTrie)
	suite.True(valid)
	suite.NoError(err)
}

func (suite *TransactionPoolTestSuite) TestTransactionValidationEdgeCases() {
	// Create a test state trie
	stateTrie := state.NewMptTrie()

	// Create a test account with maximum balance
	account := state.Account{
		Balance: ^uint64(0), // Maximum uint64 value
		Nonce:   1,
	}
	err := stateTrie.PutAccount(suite.user1Wallet.GetAddress(), &account)
	suite.NoError(err)

	// Test transaction with maximum amount
	txMaxAmount := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		^uint64(0), // Maximum uint64 value
		1,
		1,
	)
	valid, err := txMaxAmount.ValidateWithState(stateTrie)
	suite.True(valid)
	suite.NoError(err)

	// Test transaction with maximum block number
	txMaxBlock := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		100,
		1,
		^uint32(0), // Maximum uint32 value
	)
	valid, err = txMaxBlock.ValidateWithState(stateTrie)
	suite.True(valid)
	suite.NoError(err)
}
