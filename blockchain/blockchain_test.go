package blockchain

import (
	"blockchain-simulator/transactions"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

// Test account addresses used throughout the test suite
const (
	DbPath    = "./testdb"                                   // Path for test database storage
	user1     = "0x100000100000000000000000000000000000000a" // First test user address
	user2     = "0x100000100000000000000000000000000000000d" // Second test user address
	ext_user1 = "0x1000001000000000000000000000000000000001" // External test user address 1
	ext_user2 = "0x1110001000000000000000000000000000000009" // External test user address 2
	user3     = "0x1000001000000000000000000000000000000010" // Third test user address
	real_user = "0xfbB9295b7Cc91219c67cd2F6f2dec9891949769b" // Real user address for testing
)

// BlockchainTestSuite defines the test suite for blockchain functionality
// It uses testify/suite for structured testing
type BlockchainTestSuite struct {
	suite.Suite
	bc      *Blockchain // The blockchain instance being tested
	storage Storage     // Storage interface for blockchain data
}

// SetupTest initializes the test environment before each test
// - Creates a new LevelDB storage instance
// - Initializes test accounts with initial balances
// - Creates a new blockchain with genesis block
func (suite *BlockchainTestSuite) SetupTest() {
	suite.storage, _ = NewLevelDBStorage(DbPath)
	accountAddrs := []string{
		user1,
		user2,
		ext_user1,
	}
	amounts := []uint64{10, 5, 0} // Initial balances for test accounts
	suite.bc = NewBlockchain(suite.storage, accountAddrs, amounts)
}

// TearDownTest cleans up after each test
// - Closes the storage connection
// - Removes test database files
func (suite *BlockchainTestSuite) TearDownTest() {
	if suite.storage != nil {
		suite.storage.Close() // Ensure the database is closed
	}
	os.RemoveAll(DbPath)
}

// TestBlockchainTestSuite runs the entire test suite
func TestBlockchainTestSuite(t *testing.T) {
	suite.Run(t, new(BlockchainTestSuite))
}

// TestGenesisBlockCreation verifies the creation and properties of the genesis block
// - Checks block index is 0
// - Verifies previous hash is "0"
// - Validates block hash and state root are not empty
// - Confirms initial account balances are correct
func (suite *BlockchainTestSuite) TestGenesisBlockCreation() {
	genesisBlock := suite.bc.Chain[0]

	// Verify genesis block properties
	suite.Equal(uint64(0), genesisBlock.Index)
	suite.Equal("0", genesisBlock.PrevHash)
	suite.NotEmpty(genesisBlock.Hash)
	suite.NotEmpty(genesisBlock.StateRoot)
	suite.Equal(genesisBlock.StateRoot, suite.bc.StateTrie.RootHash())

	// Verify initial account balances
	senderAcc, err := suite.bc.StateTrie.GetAccount(common.HexToAddress(user1))
	suite.NoError(err)
	suite.Equal(uint64(10), senderAcc.Balance)

	receiverAcc, err := suite.bc.StateTrie.GetAccount(common.HexToAddress(user2))
	suite.NoError(err)
	suite.Equal(uint64(5), receiverAcc.Balance)
}

// TestTransactionProcessing tests the processing of a single transaction
// - Creates a transaction between two accounts
// - Processes the transaction in a new block
// - Verifies account balances are updated correctly
// - Checks nonce is incremented
func (suite *BlockchainTestSuite) TestTransactionProcessing() {
	senderAddress := common.HexToAddress(user1)
	receiverAddress := common.HexToAddress(ext_user1)

	last_block_number := suite.bc.LastBlockNumber
	if len(suite.bc.Chain) == 0 {
		suite.Fail("No genesis blocks in the chain")
	}
	prevBlock := suite.bc.Chain[last_block_number]

	// Create and process a transaction
	tx := transactions.Transaction{
		From:   senderAddress,
		To:     receiverAddress,
		Amount: 3,
		Nonce:  0,
	}

	newBlock := CreateBlock([]transactions.Transaction{tx}, prevBlock)
	ProcessBlock(newBlock, suite.bc.StateTrie)
	success, err := suite.bc.AddBlock(newBlock)
	suite.NoError(err)
	suite.True(success)

	// Verify updated account balances and nonce
	senderAcc, err := suite.bc.StateTrie.GetAccount(senderAddress)
	suite.NoError(err)
	suite.Equal(uint64(7), senderAcc.Balance) // 10 - 3
	suite.Equal(uint64(1), senderAcc.Nonce)

	receiverAcc, err := suite.bc.StateTrie.GetAccount(receiverAddress)
	suite.NoError(err)
	suite.Equal(uint64(3), receiverAcc.Balance) // 0 + 3
}

// TestBlockPersistence verifies that blocks are properly stored and retrieved
// - Creates a new block with a transaction
// - Stores the block in the database
// - Retrieves and verifies the stored block
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

	// Verify block was stored correctly
	storedBlock, err := suite.storage.GetBlock(newBlock.Hash)
	suite.NoError(err)
	suite.Equal(newBlock.Hash, storedBlock.Hash)
	suite.Equal(newBlock.Index, storedBlock.Index)
}

// TestMultipleTransactions tests processing multiple transactions in a single block
// - Creates multiple transactions from the same sender
// - Processes them in a single block
// - Verifies final balances and nonces are correct
func (suite *BlockchainTestSuite) TestMultipleTransactions() {
	sender := common.HexToAddress(user1)
	receiver := common.HexToAddress(ext_user1)

	// Create multiple transactions with sequential nonces
	txs := []transactions.Transaction{
		{From: sender, To: receiver, Amount: 3, Nonce: 0},
		{From: sender, To: receiver, Amount: 2, Nonce: 1},
	}

	latestHash := suite.bc.GetLatestBlockHash()
	prevBlock, err := suite.storage.GetBlock(latestHash)
	suite.NoError(err)

	newBlock := CreateBlock(txs, prevBlock)
	ProcessBlock(newBlock, suite.bc.StateTrie)
	success, err := suite.bc.AddBlock(newBlock)
	suite.NoError(err)
	suite.True(success)

	// Verify final account states
	senderAcc, err := suite.bc.StateTrie.GetAccount(sender)
	suite.NoError(err)
	suite.Equal(uint64(5), senderAcc.Balance) // 10 - 3 - 2
	suite.Equal(uint64(2), senderAcc.Nonce)

	receiverAcc, err := suite.bc.StateTrie.GetAccount(receiver)
	suite.NoError(err)
	suite.Equal(uint64(5), receiverAcc.Balance) // 0 + 3 + 2
	suite.Equal(uint64(0), receiverAcc.Nonce)
}

// TestGetBlockByHashNotFound tests the behavior when requesting a non-existent block
// - Attempts to retrieve a block with an invalid hash
// - Verifies that an empty block is returned
func (suite *BlockchainTestSuite) TestGetBlockByHashNotFound() {
	// Try to get a block with non-existent hash
	nonExistentHash := "non_existent_hash"
	block := suite.bc.GetBlockByHash(nonExistentHash)
	suite.Equal(Block{}, block)
}

// TestAddBlockStorageFailure tests error handling when storage operations fail
// - Creates a new block
// - Closes the storage to force failure
// - Verifies that block addition fails with an error
func (suite *BlockchainTestSuite) TestAddBlockStorageFailure() {
	// Create a new block
	tx := transactions.Transaction{
		From:   common.HexToAddress(user1),
		To:     common.HexToAddress(ext_user1),
		Amount: 5,
		Nonce:  0,
	}

	prevBlock := suite.bc.GetLatestBlock()
	newBlock := CreateBlock([]transactions.Transaction{tx}, prevBlock)

	// Close storage to force failure
	suite.storage.Close()

	// Try to add block with closed storage
	success, err := suite.bc.AddBlock(newBlock)
	suite.Error(err)
	suite.False(success)
}

// TestGetLatestBlock verifies the retrieval of the most recent block
// - Gets the latest block
// - Verifies it matches the last block in the chain
// - Checks block properties are correct
func (suite *BlockchainTestSuite) TestGetLatestBlock() {
	// Get the latest block
	latestBlock := suite.bc.GetLatestBlock()

	block := suite.bc.GetBlockByHash(latestBlock.Hash)
    suite.Equal(block, latestBlock)
	// Verify it matches the last block in chain
	suite.Equal(suite.bc.Chain[suite.bc.LastBlockNumber], latestBlock)

	// Verify block properties
	suite.Equal(suite.bc.LastBlockNumber, latestBlock.Index)
	suite.NotEmpty(latestBlock.Hash)
	suite.NotEmpty(latestBlock.StateRoot)
}
