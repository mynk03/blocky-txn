package blockchain

import (
	"blockchain-simulator/transactions"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

const (
	DbPath    = "./testdb"
	user1     = "0x100000100000000000000000000000000000000a"
	user2     = "0x100000100000000000000000000000000000000d"
	ext_user1 = "0x1000001000000000000000000000000000000001"
	ext_user2 = "0x1110001000000000000000000000000000000009"
	user3     = "0x1000001000000000000000000000000000000010"
	real_user = "0xfbB9295b7Cc91219c67cd2F6f2dec9891949769b"
)

// Define the test suite
type BlockchainTestSuite struct {
	suite.Suite
	bc      *Blockchain
	storage Storage
}

// Setup the test suite
func (suite *BlockchainTestSuite) SetupTest() {
	suite.storage, _ = NewLevelDBStorage(DbPath)
	accountAddrs := []string{
		user1,
		user2,
		ext_user1,
	}
	amounts := []uint64{10, 5, 0}
	suite.bc = NewBlockchain(suite.storage, accountAddrs, amounts)
}

// Cleanup after each test
func (suite *BlockchainTestSuite) TearDownTest() {
    if suite.storage != nil {
		suite.storage.Close() // Ensure the database is closed
	}	
	os.RemoveAll(DbPath)
}

// Run the test suite
func TestBlockchainTestSuite(t *testing.T) {
	suite.Run(t, new(BlockchainTestSuite))
}

// Test methods
func (suite *BlockchainTestSuite) TestGenesisBlockCreation() {
	genesisBlock := suite.bc.Chain[0]

	// Verify genesis block
	suite.Equal(uint64(0), genesisBlock.Index)
	suite.Equal("0", genesisBlock.PrevHash)
	suite.NotEmpty(genesisBlock.Hash)
	suite.NotEmpty(genesisBlock.StateRoot)
	suite.Equal(genesisBlock.StateRoot, suite.bc.StateTrie.RootHash())

	// verify balances with error handling
	senderAcc, err := suite.bc.StateTrie.GetAccount(common.HexToAddress(user1))
	suite.NoError(err)
	suite.Equal(uint64(10), senderAcc.Balance)

	receiverAcc, err := suite.bc.StateTrie.GetAccount(common.HexToAddress(user2))
	suite.NoError(err)
	suite.Equal(uint64(5), receiverAcc.Balance)
}

func (suite *BlockchainTestSuite) TestTransactionProcessing() {

	senderAddress := common.HexToAddress(user1)
	receiverAddress := common.HexToAddress(ext_user1)

	last_block_number := suite.bc.LastBlockNumber
	if len(suite.bc.Chain) == 0 {
		suite.Fail("No genesis blocks in the chain")
	}
	prevBlock := suite.bc.Chain[last_block_number]

	tx := transactions.Transaction{
		From:   senderAddress,
		To:     receiverAddress,
		Amount: 3,
		Nonce:  0,
	}

	newBlock := CreateBlock([]transactions.Transaction{tx}, prevBlock)
	success, err := suite.bc.AddBlock(newBlock)
	suite.NoError(err)
	suite.True(success)

	// Verify account balances after transaction with error handling
	senderAcc, err := suite.bc.StateTrie.GetAccount(senderAddress)
	suite.NoError(err)
	suite.Equal(uint64(7), senderAcc.Balance) // 10 - 3
	suite.Equal(uint64(1), senderAcc.Nonce)

	receiverAcc, err := suite.bc.StateTrie.GetAccount(receiverAddress)
	suite.NoError(err)
	suite.Equal(uint64(3), receiverAcc.Balance) // 0 + 3
}

func (suite *BlockchainTestSuite) TestBlockPersistence() {
	// Create and add a new block
	tx := transactions.Transaction{
		From:   common.HexToAddress(user1),
		To:     common.HexToAddress(ext_user1),
		Amount: 5,
		Nonce:  0,
	}

	latestHash := suite.bc.GetLatestBlockHash()
	prevBlock, err := suite.storage.GetBlock(latestHash)
	suite.NoError(err)

	newBlock := CreateBlock([]transactions.Transaction{tx}, prevBlock)
	success, err := suite.bc.AddBlock(newBlock)
	suite.NoError(err)
	suite.True(success)

	// Verify block was stored
	storedBlock, err := suite.storage.GetBlock(newBlock.Hash)
	suite.NoError(err)
	suite.Equal(newBlock.Hash, storedBlock.Hash)
	suite.Equal(newBlock.Index, storedBlock.Index)
}

func (suite *BlockchainTestSuite) TestMultipleTransactions() {
	sender := common.HexToAddress(user1)
	receiver := common.HexToAddress(ext_user1)

	// Create multiple transactions
	txs := []transactions.Transaction{
		{From: sender, To: receiver, Amount: 3, Nonce: 0},
		{From: sender, To: receiver, Amount: 2, Nonce: 1},
	}

	latestHash := suite.bc.GetLatestBlockHash()
	prevBlock, err := suite.storage.GetBlock(latestHash)
	suite.NoError(err)

	newBlock := CreateBlock(txs, prevBlock)
	success, err := suite.bc.AddBlock(newBlock)
	suite.NoError(err)
	suite.True(success)

	// Verify final balances with error handling
	senderAcc, err := suite.bc.StateTrie.GetAccount(sender)
	suite.NoError(err)
	suite.Equal(uint64(5), senderAcc.Balance) // 10 - 3 - 2
	suite.Equal(uint64(2), senderAcc.Nonce)

	receiverAcc, err := suite.bc.StateTrie.GetAccount(receiver)
	suite.NoError(err)
	suite.Equal(uint64(5), receiverAcc.Balance) // 0 + 3 + 2
	suite.Equal(uint64(0), receiverAcc.Nonce)
}

func (suite *BlockchainTestSuite) TestInvalidTransactions() {
	// Test transaction with insufficient balance
	tx := transactions.Transaction{
		From:   common.HexToAddress(user1),
		To:     common.HexToAddress(ext_user1),
		Amount: 20, // More than available balance
		Nonce:  0,
	}

	latestHash := suite.bc.GetLatestBlockHash()
	prevBlock, err := suite.storage.GetBlock(latestHash)
	suite.NoError(err)

	newBlock := CreateBlock([]transactions.Transaction{tx}, prevBlock)
	success, _ := suite.bc.AddBlock(newBlock)
	suite.False(success) // Should fail due to insufficient balance

	// Test transaction with invalid nonce
	tx = transactions.Transaction{
		From:   common.HexToAddress(user1),
		To:     common.HexToAddress(user2),
		Amount: 5,
		Nonce:  1, // Invalid nonce (should be 0)
	}

	newBlock = CreateBlock([]transactions.Transaction{tx}, prevBlock)
	success, _ = suite.bc.AddBlock(newBlock)
	suite.False(success) // Should fail due to invalid nonce
}
