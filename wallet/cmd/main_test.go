package main

import (
	"blockchain-simulator/transaction"
	"blockchain-simulator/wallet"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

type MainTestSuite struct {
	suite.Suite
	testDir string
}

func (suite *MainTestSuite) SetupTest() {
	// Create a temporary directory for test files
	suite.testDir = filepath.Join(os.TempDir(), "blockchain-simulator-test")
	err := os.MkdirAll(suite.testDir, 0755)
	suite.NoError(err)

	// Set environment variables for testing
	os.Setenv("TOTAL_WALLETS", "2")
	os.Setenv("TOTAL_TRANSACTIONS", "2")
	os.Setenv("WALLETS_PATH", filepath.Join(suite.testDir, "wallets.json"))
	os.Setenv("TRANSACTIONS_PATH", filepath.Join(suite.testDir, "transactions.json"))
}

func (suite *MainTestSuite) TearDownTest() {
	// Clean up test files
	os.RemoveAll(suite.testDir)
}

func TestMainTestSuite(t *testing.T) {
	suite.Run(t, new(MainTestSuite))
}

func (suite *MainTestSuite) TestGetEnv() {
	// Test with existing environment variable
	os.Setenv("TEST_KEY", "test_value")
	suite.Equal("test_value", getEnv("TEST_KEY", "default"))

	// Test with non-existent environment variable
	suite.Equal("default", getEnv("NON_EXISTENT_KEY", "default"))

	// Test with empty environment variable
	os.Setenv("EMPTY_KEY", "")
	suite.Equal("default", getEnv("EMPTY_KEY", "default"))
}

func (suite *MainTestSuite) TestCreateJsonFile() {
	// Capture stdout for error logging tests
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	suite.NoError(err)
	os.Stdout = w

	// Test creating a new JSON file
	filePath := filepath.Join(suite.testDir, "test.json")
	createJsonFile(filePath)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = originalStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)
	suite.Contains(buf.String(), "Creating a json file ...")

	// Verify file exists
	_, err = os.Stat(filePath)
	suite.NoError(err)

	// Reset stdout capture for next test
	r, w, err = os.Pipe()
	suite.NoError(err)
	os.Stdout = w

	// Test creating file in non-existent directory
	invalidPath := filepath.Join(suite.testDir, "nonexistent", "test.json")
	createJsonFile(invalidPath)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = originalStdout
	buf.Reset()
	io.Copy(&buf, r)
	suite.Contains(buf.String(), "Creating a json file ...")

	// Reset stdout capture for next test
	r, w, err = os.Pipe()
	suite.NoError(err)
	os.Stdout = w

	// Test creating file with invalid permissions
	readOnlyPath := filepath.Join(suite.testDir, "readonly.json")
	os.MkdirAll(filepath.Dir(readOnlyPath), 0444)
	createJsonFile(readOnlyPath)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = originalStdout
	buf.Reset()
	io.Copy(&buf, r)
	suite.Contains(buf.String(), "Creating a json file ...")
}

func (suite *MainTestSuite) TestCreateAndStoreWallets() {
	// Test creating wallets
	wallets := createAndStoreWallets(2, filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(wallets)
	suite.Len(wallets, 2)

	// Verify wallet data
	for _, wallet := range wallets {
		suite.NotEmpty(wallet.PrivateKey)
		suite.NotEmpty(wallet.Address)
		suite.Equal(uint64(100), wallet.Balance)
		suite.Equal(uint64(0), wallet.Nonce)
	}

	// Test with invalid number of wallets
	wallets = createAndStoreWallets(0, filepath.Join(suite.testDir, "invalid.json"))
	suite.Equal(0, len(wallets))

	// Test with invalid file path
	wallets = createAndStoreWallets(2, filepath.Join("/nonexistent", "wallets.json"))
	suite.Nil(wallets)
}

func (suite *MainTestSuite) TestReadWallets() {
	// First create wallets
	wallets := createAndStoreWallets(2, filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(wallets)

	// Test reading wallets
	readWallets := ReadWallets(filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(readWallets)
	suite.Len(readWallets, 2)

	// Test reading non-existent file
	readWallets = ReadWallets(filepath.Join(suite.testDir, "nonexistent.json"))
	suite.Nil(readWallets)

	// Test reading invalid JSON file
	invalidJSONPath := filepath.Join(suite.testDir, "invalid.json")
	os.WriteFile(invalidJSONPath, []byte("invalid json"), 0644)
	readWallets = ReadWallets(invalidJSONPath)
	suite.Nil(readWallets)
}

func (suite *MainTestSuite) TestCreateTransactions() {
	// First create wallets
	wallets := createAndStoreWallets(2, filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(wallets)

	// Read wallets
	walletsFromJSON := ReadWallets(filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(walletsFromJSON)

	// Test creating transactions
	transactions := createTransactions(wallets, walletsFromJSON, 2)
	suite.NotNil(transactions)
	suite.Len(transactions, 2)

	// Verify transaction data
	for _, tx := range transactions {
		suite.NotEmpty(tx.TransactionHash)
		suite.NotEmpty(tx.Sender)
		suite.NotEmpty(tx.Receiver)
		suite.Equal(uint64(10), tx.Amount)
		suite.NotEmpty(tx.Signature)
	}

	// Test case: Verify that createTransactions returns nil when validation fails
	// Create a wallet with nil private key to force validation failure
	invalidWallet := &wallet.MockWallet{} // This will have nil private key

	// Replace one of the wallets with our invalid wallet
	wallets[0].Wallet = *invalidWallet

	// Try to create transactions with the invalid wallet
	invalidTransactions := createTransactions(wallets, walletsFromJSON, 2)
	suite.Nil(invalidTransactions, "createTransactions should return nil when validation fails")
}

func (suite *MainTestSuite) TestStoreTransactions() {
	// First create wallets and transactions
	wallets := createAndStoreWallets(2, filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(wallets)

	walletsFromJSON := ReadWallets(filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(walletsFromJSON)

	transactions := createTransactions(wallets, walletsFromJSON, 2)
	suite.NotNil(transactions)

	// Capture stdout for error logging tests
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	suite.NoError(err)
	os.Stdout = w

	// Test storing transactions
	storeTransactions(transactions, filepath.Join(suite.testDir, "transactions.json"))

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = originalStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)
	suite.Contains(buf.String(), "Storing transactions in a json file ...")
	suite.Contains(buf.String(), "Transactions stored in ")

	// Verify file exists and has content
	fileInfo, err := os.Stat(filepath.Join(suite.testDir, "transactions.json"))
	suite.NoError(err)
	suite.Greater(fileInfo.Size(), int64(0))

	// Reset stdout capture for next test
	r, w, err = os.Pipe()
	suite.NoError(err)
	os.Stdout = w

	// Test storing empty transactions
	storeTransactions([]TransactionRequest{}, filepath.Join(suite.testDir, "empty.json"))

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = originalStdout
	buf.Reset()
	io.Copy(&buf, r)
	suite.Contains(buf.String(), "Storing transactions in a json file ...")
	suite.Contains(buf.String(), "Transactions stored in ")

	fileInfo, err = os.Stat(filepath.Join(suite.testDir, "empty.json"))
	suite.NoError(err)
	suite.Greater(fileInfo.Size(), int64(0))

	// Reset stdout capture for next test
	r, w, err = os.Pipe()
	suite.NoError(err)
	os.Stdout = w

	// Test storing to invalid path
	storeTransactions(transactions, filepath.Join("/nonexistent", "transactions.json"))

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = originalStdout
	buf.Reset()
	io.Copy(&buf, r)
	suite.Contains(buf.String(), "Storing transactions in a json file ...")
}

func (suite *MainTestSuite) TestMain() {
	// Test main function
	main()

	// Verify that files were created
	_, err := os.Stat(filepath.Join(suite.testDir, "wallets.json"))
	suite.NoError(err)

	_, err = os.Stat(filepath.Join(suite.testDir, "transactions.json"))
	suite.NoError(err)

	// Test with invalid environment variables
	os.Setenv("TOTAL_WALLETS", "invalid")
	main()
}

func (suite *MainTestSuite) TestTransactionRequestValidation() {
	// Create a test transaction request
	txRequest := TransactionRequest{
		TransactionHash: "0x123",
		Sender:          common.Address{}.Hex(),
		Receiver:        common.Address{}.Hex(),
		Amount:          10,
		Nonce:           1,
		Timestamp:       1234567890,
		Signature:       "0x456",
	}

	// Verify transaction request fields
	suite.Equal("0x123", txRequest.TransactionHash)
	suite.Equal(common.Address{}.Hex(), txRequest.Sender)
	suite.Equal(common.Address{}.Hex(), txRequest.Receiver)
	suite.Equal(uint64(10), txRequest.Amount)
	suite.Equal(uint64(1), txRequest.Nonce)
	suite.Equal(uint64(1234567890), txRequest.Timestamp)
	suite.Equal("0x456", txRequest.Signature)

	// Test with zero values
	txRequest = TransactionRequest{}
	suite.Empty(txRequest.TransactionHash)
	suite.Empty(txRequest.Sender)
	suite.Empty(txRequest.Receiver)
	suite.Equal(uint64(0), txRequest.Amount)
	suite.Equal(uint64(0), txRequest.Nonce)
	suite.Equal(uint64(0), txRequest.Timestamp)
	suite.Empty(txRequest.Signature)
}

func (suite *MainTestSuite) TestTransactionSigningAndVerification() {
	// First create wallets
	wallets := createAndStoreWallets(2, filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(wallets)

	// Read wallets
	walletsFromJSON := ReadWallets(filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(walletsFromJSON)

	// Test case 1: Invalid transaction hash
	invalidTx := transaction.Transaction{}
	invalidTx.TransactionHash = "invalid_hash"

	wrongWallet := wallet.MockWallet{}

	// Try to sign with invalid hash
	signature, err := wrongWallet.SignTransaction(common.HexToHash(invalidTx.TransactionHash))
	suite.Error(err)
	suite.Nil(signature)

	// Test case 2: Transaction with empty signature
	emptySigTx := transaction.Transaction{
		Sender:    common.HexToAddress(wallets[0].Wallet.GetAddress().Hex()),
		Receiver:  common.HexToAddress(wallets[1].Wallet.GetAddress().Hex()),
		Amount:    10,
		Nonce:     wallets[0].Nonce,
		Timestamp: uint64(time.Now().Unix()),
	}
	emptySigTx.TransactionHash = emptySigTx.GenerateHash()
	valid, err := emptySigTx.Verify()
	suite.Error(err)
	suite.False(valid)

	// Test case 3: Transaction with invalid signature
	invalidSigTx := transaction.Transaction{
		Sender:    common.HexToAddress(wallets[0].Wallet.GetAddress().Hex()),
		Receiver:  common.HexToAddress(wallets[1].Wallet.GetAddress().Hex()),
		Amount:    10,
		Nonce:     wallets[0].Nonce,
		Timestamp: uint64(time.Now().Unix()),
	}
	invalidSigTx.TransactionHash = invalidSigTx.GenerateHash()
	invalidSigTx.Signature = []byte("invalid_signature")
	valid, err = invalidSigTx.Verify()
	suite.Error(err)
	suite.False(valid)

	// Test case 4: Transaction with mismatched sender
	mismatchedTx := transaction.Transaction{
		Sender:    common.HexToAddress(wallets[1].Wallet.GetAddress().Hex()), // Using wrong sender
		Receiver:  common.HexToAddress(wallets[0].Wallet.GetAddress().Hex()),
		Amount:    10,
		Nonce:     wallets[0].Nonce,
		Timestamp: uint64(time.Now().Unix()),
	}
	mismatchedTx.TransactionHash = mismatchedTx.GenerateHash()
	// Sign with wallet[0] but set sender as wallet[1]
	signature, err = wallets[0].Wallet.SignTransaction(common.HexToHash(mismatchedTx.TransactionHash))
	suite.NoError(err)
	mismatchedTx.Signature = signature
	valid, err = mismatchedTx.Verify()
	suite.NoError(err)
	suite.False(valid) // Should fail because signature doesn't match sender

	// Test case 5: Transaction with modified data after signing
	validTx := transaction.Transaction{
		Sender:    common.HexToAddress(wallets[0].Wallet.GetAddress().Hex()),
		Receiver:  common.HexToAddress(wallets[1].Wallet.GetAddress().Hex()),
		Amount:    10,
		Nonce:     wallets[0].Nonce,
		Timestamp: uint64(time.Now().Unix()),
	}
	validTx.TransactionHash = validTx.GenerateHash()
	signature, err = wallets[0].Wallet.SignTransaction(common.HexToHash(validTx.TransactionHash))
	suite.NoError(err)
	validTx.Signature = signature
	valid, err = validTx.Verify()
	suite.NoError(err)
	suite.True(valid)

	// Modify the transaction after signing
	validTx.Amount = 20
	valid, err = validTx.Verify()
	suite.NoError(err)
	suite.False(valid) // Should fail because data was modified

}

func (suite *MainTestSuite) TestCreateTransactionsErrorLogging() {
	// First create wallets
	wallets := createAndStoreWallets(2, filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(wallets)

	// Read wallets
	walletsFromJSON := ReadWallets(filepath.Join(suite.testDir, "wallets.json"))
	suite.NotNil(walletsFromJSON)

	// Capture stdout for error logging tests
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	suite.NoError(err)
	os.Stdout = w

	// Test transaction validation failure
	// Create a wallet with nil private key to force validation failure
	invalidWallet := &wallet.MockWallet{} // This will have nil private key
	wallets[0].Wallet = *invalidWallet

	// Try to create transactions with the invalid wallet
	invalidTransactions := createTransactions(wallets, walletsFromJSON, 2)
	suite.Nil(invalidTransactions)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = originalStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)
	suite.Contains(buf.String(), "Error signing transaction:")
}