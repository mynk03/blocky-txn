package blockchain

import (
	"blockchain-simulator/transaction"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

// Test account addresses used throughout the test suite
const (
	testChainDataPath = "./testdata"                                 // Path for test database storage
	testUser1         = "0x100000100000000000000000000000000000000a" // First test user address
	testUser2         = "0x100000100000000000000000000000000000000d" // Second test user address
	testUser3         = "0x1000001000000000000000000000000000000010" // Third test user address
)

type LevelDBTestSuite struct {
	suite.Suite
	storage *LevelDBStorage
}

func TestLevelDBTestSuite(t *testing.T) {
	suite.Run(t, new(LevelDBTestSuite))
}

func (suite *LevelDBTestSuite) SetupTest() {
	// Create a new LevelDB storage instance for each test
	storage, err := NewLevelDBStorage(testChainDataPath)
	suite.NoError(err)
	suite.storage = storage
}

func (suite *LevelDBTestSuite) TearDownTest() {
	// Clean up after each test
	suite.storage.Close()
	os.RemoveAll(testChainDataPath)
}

func (suite *LevelDBTestSuite) TestNewLevelDBStorage() {
	suite.NotNil(suite.storage)
	suite.storage.Close()

	// Test creating storage with invalid path
	storage1, err := NewLevelDBStorage("")
	suite.Error(err)
	suite.Nil(storage1)
}

func (suite *LevelDBTestSuite) TestPutAndGetBlock() {
	// Create a test block
	block := Block{
		Index:     1,
		Timestamp: "2024-03-26T12:00:00Z",
		PrevHash:  "0x123",
		Hash:      "0x456",
		StateRoot: "0x789",
	}

	// Test putting a block
	err := suite.storage.PutBlock(block)
	suite.NoError(err)

	// Test getting the block
	retrievedBlock, err := suite.storage.GetBlock(block.Hash)
	suite.NoError(err)
	suite.Equal(block, retrievedBlock)

	// Test getting non-existent block
	retrievedBlock, err = suite.storage.GetBlock("0x999")
	suite.Error(err)
	suite.Equal(Block{}, retrievedBlock)
}

func (suite *LevelDBTestSuite) TestGetLatestBlock() {
	// Test getting latest block when no blocks exist
	block, err := suite.storage.GetLatestBlock()
	suite.Error(err)
	suite.Equal(Block{}, block)

	// Create and store multiple blocks
	blocks := []Block{
		{
			Index:     1,
			Timestamp: "2024-03-26T12:00:00Z",
			PrevHash:  "0x123",
			Hash:      "0x456",
			StateRoot: "0x789",
		},
		{
			Index:     2,
			Timestamp: "2024-03-26T12:01:00Z",
			PrevHash:  "0x456",
			Hash:      "0x789",
			StateRoot: "0xabc",
		},
	}

	for _, block := range blocks {
		err := suite.storage.PutBlock(block)
		suite.NoError(err)
	}

	// Test getting latest block
	latestBlock, err := suite.storage.GetLatestBlock()
	suite.NoError(err)
	suite.Equal(blocks[1], latestBlock)
}

func (suite *LevelDBTestSuite) TestPutAndGetTransaction() {
	// Create a test transaction
	tx := transaction.Transaction{
		From:        common.HexToAddress(testUser1),
		To:          common.HexToAddress(testUser2),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}
	tx.TransactionHash = tx.GenerateHash()

	// Test putting a transaction
	err := suite.storage.PutTransaction(tx)
	suite.NoError(err)

	// Test getting the transaction
	retrievedTx, err := suite.storage.GetTransaction(tx.TransactionHash)
	suite.NoError(err)
	suite.Equal(tx, retrievedTx)

	// Test getting non-existent transaction
	retrievedTx, err = suite.storage.GetTransaction("0x999")
	suite.Error(err)
	suite.Equal(transaction.Transaction{}, retrievedTx)
}

func (suite *LevelDBTestSuite) TestGetPendingTransactions() {
	// Create test transactions
	txs := []transaction.Transaction{
		{
			From:        common.HexToAddress(testUser1),
			To:          common.HexToAddress(testUser3),
			Amount:      100,
			Nonce:       1,
			BlockNumber: 1,
			Timestamp:   1234567890,
		},
		{
			From:        common.HexToAddress(testUser2),
			To:          common.HexToAddress(testUser3),
			Amount:      200,
			Nonce:       1,
			BlockNumber: 1,
			Timestamp:   1234567891,
		},
	}

	// Store transactions as pending
	err := suite.storage.PutPendingTransactions(txs)
	suite.NoError(err)

	// Test getting pending transactions
	pendingTxs, err := suite.storage.GetPendingTransactions()
	suite.NoError(err)
	suite.Len(pendingTxs, 2)
	suite.Contains(pendingTxs, txs[0])
	suite.Contains(pendingTxs, txs[1])
}

func (suite *LevelDBTestSuite) TestRemoveTransaction() {
	// Create a test transaction
	tx := transaction.Transaction{
		From:        common.HexToAddress(testUser1),
		To:          common.HexToAddress(testUser2),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}
	tx.TransactionHash = tx.GenerateHash()

	// Store the transaction
	err := suite.storage.PutTransaction(tx)
	suite.NoError(err)

	// Remove the transaction
	err = suite.storage.RemoveTransaction(tx.TransactionHash)
	suite.NoError(err)

	// Verify transaction is removed
	retrievedTx, err := suite.storage.GetTransaction(tx.TransactionHash)
	suite.Error(err)
	suite.Equal(transaction.Transaction{}, retrievedTx)
}

func (suite *LevelDBTestSuite) TestRemoveBulkTransactions() {
	// Create test transactions
	txs := []transaction.Transaction{
		{
			From:        common.HexToAddress(testUser1),
			To:          common.HexToAddress(testUser2),
			Amount:      100,
			Nonce:       1,
			BlockNumber: 1,
			Timestamp:   1234567890,
		},
		{
			From:        common.HexToAddress(testUser2),
			To:          common.HexToAddress(testUser3),
			Amount:      200,
			Nonce:       1,
			BlockNumber: 1,
			Timestamp:   1234567891,
		},
	}

	// Store transactions
	hashes := make([]string, len(txs))
	for i, tx := range txs {
		tx.TransactionHash = tx.GenerateHash()
		hashes[i] = tx.TransactionHash
		err := suite.storage.PutTransaction(tx)
		suite.NoError(err)
	}

	// Remove transactions in bulk
	err := suite.storage.RemoveBulkTransactions(hashes)
	suite.NoError(err)

	// Verify transactions are removed
	for _, hash := range hashes {
		retrievedTx, err := suite.storage.GetTransaction(hash)
		suite.Error(err)
		suite.Equal(transaction.Transaction{}, retrievedTx)
	}
}

func (suite *LevelDBTestSuite) TestClose() {
	// Test closing the storage
	err := suite.storage.Close()
	suite.NoError(err)

	// Test operations after closing
	block := Block{
		Index:     1,
		Timestamp: "2024-03-26T12:00:00Z",
		PrevHash:  "0x123",
		Hash:      "0x456",
		StateRoot: "0x789",
	}

	err = suite.storage.PutBlock(block)
	suite.Error(err)

	_, err = suite.storage.GetBlock(block.Hash)
	suite.Error(err)

	_, err = suite.storage.GetLatestBlock()
	suite.Error(err)
}

func (suite *LevelDBTestSuite) TestErrorCases() {
	// Test invalid block data
	invalidBlock := Block{
		Index:     1,
		Timestamp: "invalid timestamp",
		PrevHash:  "0x123",
		Hash:      "0x456",
		StateRoot: "0x789",
	}

	err := suite.storage.PutBlock(invalidBlock)
	suite.NoError(err) // LevelDB should still store invalid data

	// Test invalid transaction data
	invalidTx := transaction.Transaction{
		From:        common.Address{}, // Empty address
		To:          common.Address{}, // Empty address
		Amount:      0,
		Nonce:       0,
		BlockNumber: 0,
		Timestamp:   0,
	}
	invalidTx.TransactionHash = invalidTx.GenerateHash()

	err = suite.storage.PutTransaction(invalidTx)
	suite.NoError(err) // LevelDB should still store invalid data

	// Test storage operations with invalid paths
	invalidStorage, err := NewLevelDBStorage("")
	suite.Error(err)
	suite.Nil(invalidStorage)
}
