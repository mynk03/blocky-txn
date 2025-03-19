package blockchain

import (
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

const DbPath = "./testdb"
const user1 = "0x100000000000000000000000000000000000000a"
const user2 = "0x100000000000000000000000000000000000000b"

// Define the test suite
type BlockchainTestSuite struct {
	suite.Suite
	bc      *Blockchain
	storage Storage
}

// Setup the test suite
func (suite *BlockchainTestSuite) SetupTest() {
	suite.storage, _ = newLevelDBStorage(DbPath)
	accountAddrs := []string{
		user1,
		user2,
	}
	amounts := []uint64{10, 5}
	suite.bc = NewBlockchain(suite.storage, accountAddrs, amounts)
}

// Cleanup after each test
func (suite *BlockchainTestSuite) TearDownTest() {
	if ldb, ok := suite.storage.(*LevelDBStorage); ok {
		ldb.db.Close()
	}
}

// Test methods
func (suite *BlockchainTestSuite) TestGenesisBlockCreation() {
	// TotalBlocks := suite.bc.TotalBlocks;
	// latestHash := suite.bc.GetLatestHash()
	genesisBlock := suite.bc.Chain[0]
	// suite.NoError(err)

	// Verify genesis block
	suite.Equal(int(0), genesisBlock.Index)
	suite.Equal("0", genesisBlock.PrevHash)
	suite.NotEmpty(genesisBlock.Hash)
	suite.NotEmpty(genesisBlock.StateRoot)
	suite.Equal(genesisBlock.StateRoot, suite.bc.StateTrie.RootHash())
	suite.Equal(uint64(10), suite.bc.StateTrie.GetAccount(common.HexToAddress(user1)).Balance)
	suite.Equal(uint64(5), suite.bc.StateTrie.GetAccount(common.HexToAddress(user2)).Balance)
}

func (suite *BlockchainTestSuite) TestTransactionProcessing() {
	sender := common.HexToAddress(user1)
	receiver := common.HexToAddress(user2)

	latestHash := suite.bc.GetLatestHash()

	tx := Transaction{
		From:   sender,
		To:     receiver,
		Amount: 5,
		Nonce:  0,
	}

	prevBlock, err := suite.storage.GetBlock(latestHash)
	fmt.Println("Test Here 0 error in the getting previous block", err, "prevBlock", prevBlock)
	suite.NoError(err)

	newBlock := CreateBlock([]Transaction{tx}, prevBlock, suite.bc.StateTrie)
	fmt.Println("Test Here 1 error in the adding block", newBlock)
	success := suite.bc.AddBlock(newBlock)
	fmt.Println("Test Here 2 error in the adding block", success)
	suite.True(success)

	// Verify account balances after transaction
	senderAcc := suite.bc.StateTrie.GetAccount(sender)
	suite.Equal(uint64(5), senderAcc.Balance) // 10 - 5
	suite.Equal(uint64(1), senderAcc.Nonce)

	receiverAcc := suite.bc.StateTrie.GetAccount(receiver)
	suite.Equal(uint64(10), receiverAcc.Balance) // 5 + 5
}

func (suite *BlockchainTestSuite) TestBlockPersistence() {
	// Create and add a new block
	tx := Transaction{
		From:   common.HexToAddress("0x100000000000000000000000000000000000000a"),
		To:     common.HexToAddress("0x100000000000000000000000000000000000000b"),
		Amount: 5,
		Nonce:  0,
	}

	latestHash := suite.bc.GetLatestHash()
	prevBlock, err := suite.storage.GetBlock(latestHash)
	suite.NoError(err)

	newBlock := CreateBlock([]Transaction{tx}, prevBlock, suite.bc.StateTrie)
	success := suite.bc.AddBlock(newBlock)
	suite.True(success)

	// Verify block was stored
	storedBlock, err := suite.storage.GetBlock(newBlock.Hash)
	suite.NoError(err)
	suite.Equal(newBlock.Hash, storedBlock.Hash)
	suite.Equal(newBlock.Index, storedBlock.Index)
}

func (suite *BlockchainTestSuite) TestInvalidTransactions() {
	// Test transaction with insufficient balance
	tx := Transaction{
		From:   common.HexToAddress("0x100000000000000000000000000000000000000a"),
		To:     common.HexToAddress("0x100000000000000000000000000000000000000b"),
		Amount: 20, // More than available balance
		Nonce:  0,
	}

	latestHash := suite.bc.GetLatestHash()
	prevBlock, err := suite.storage.GetBlock(latestHash)
	suite.NoError(err)

	newBlock := CreateBlock([]Transaction{tx}, prevBlock, suite.bc.StateTrie)
	success := suite.bc.AddBlock(newBlock)
	suite.False(success) // Should fail due to insufficient balance

	// Test transaction with invalid nonce
	tx = Transaction{
		From:   common.HexToAddress("0x100000000000000000000000000000000000000a"),
		To:     common.HexToAddress("0x100000000000000000000000000000000000000b"),
		Amount: 5,
		Nonce:  1, // Invalid nonce (should be 0)
	}

	newBlock = CreateBlock([]Transaction{tx}, prevBlock, suite.bc.StateTrie)
	success = suite.bc.AddBlock(newBlock)
	suite.False(success) // Should fail due to invalid nonce
}

func (suite *BlockchainTestSuite) TestMultipleTransactions() {
	sender := common.HexToAddress("0x100000000000000000000000000000000000000a")
	receiver := common.HexToAddress("0x100000000000000000000000000000000000000b")

	// Create multiple transactions
	txs := []Transaction{
		{From: sender, To: receiver, Amount: 3, Nonce: 0},
		{From: sender, To: receiver, Amount: 2, Nonce: 1},
	}

	latestHash := suite.bc.GetLatestHash()
	prevBlock, err := suite.storage.GetBlock(latestHash)
	suite.NoError(err)

	newBlock := CreateBlock(txs, prevBlock, suite.bc.StateTrie)
	success := suite.bc.AddBlock(newBlock)
	suite.True(success)

	// Verify final balances
	senderAcc := suite.bc.StateTrie.GetAccount(sender)
	suite.Equal(uint64(5), senderAcc.Balance) // 10 - 3 - 2
	suite.Equal(uint64(2), senderAcc.Nonce)

	receiverAcc := suite.bc.StateTrie.GetAccount(receiver)
	suite.Equal(uint64(10), receiverAcc.Balance) // 5 + 3 + 2
	suite.Equal(uint64(0), receiverAcc.Nonce)
}

// Run the test suite
func TestBlockchainTestSuite(t *testing.T) {
	suite.Run(t, new(BlockchainTestSuite))
}
