package blockchain

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

const DbPath = "./testdb"

func setupTestBlockchain(t *testing.T) (*Blockchain, Storage) {
	// Initialize storage
	storage, err := NewLevelDBStorage(DbPath)
	assert.NoError(t, err)

	// Create initial accounts with funds
	accountAddrs := []string{
		"0x100000000000000000000000000000000000000a",
		"0x100000000000000000000000000000000000000b",
	}
	amounts := []uint64{10, 5}

	bc := NewBlockchain(storage, accountAddrs, amounts)
	assert.NotNil(t, bc)

	return bc, storage
}

// clean up the test database
func cleanupTest(storage Storage) {
	if ldb, ok := storage.(*LevelDBStorage); ok {
		ldb.db.Close()
		// os.RemoveAll(DbPath)
	}
}

func TestGenesisBlockCreation(t *testing.T) {
	bc, storage := setupTestBlockchain(t)
	defer cleanupTest(storage)

	// Get genesis block from storage
	latestHash := bc.GetLatestHash()
	genesisBlock, err := storage.GetBlock(latestHash)
	assert.NoError(t, err)

	// Verify genesis block
	assert.Equal(t, int(0), genesisBlock.Index)
	assert.Equal(t, "0", genesisBlock.PrevHash)
	assert.NotEmpty(t, genesisBlock.Hash)
	assert.NotEmpty(t, genesisBlock.StateRoot)
	assert.Equal(t, uint64(10), bc.StateTrie.GetAccount(common.HexToAddress("0x100000000000000000000000000000000000000a")).Balance)
	assert.Equal(t, uint64(5), bc.StateTrie.GetAccount(common.HexToAddress("0x100000000000000000000000000000000000000b")).Balance)
}

func TestTransactionProcessing(t *testing.T) {
	bc, storage := setupTestBlockchain(t)
	defer cleanupTest(storage)

	// Create a transaction
	sender := common.HexToAddress("0x100000000000000000000000000000000000000a")
	receiver := common.HexToAddress("0x100000000000000000000000000000000000000b")

	tx := Transaction{
		From:   sender,
		To:     receiver,
		Amount: 5,
		Nonce:  0,
	}

	// Create and add new block with transaction
	latestHash := bc.GetLatestHash()
	prevBlock, err := storage.GetBlock(latestHash)
	assert.NoError(t, err)

	newBlock := CreateBlock([]Transaction{tx}, prevBlock)
	success := bc.AddBlock(newBlock)
	assert.True(t, success)

	// Verify account balances after transaction
	senderAcc := bc.StateTrie.GetAccount(sender)
	assert.Equal(t, uint64(5), senderAcc.Balance) // 10 - 5
	assert.Equal(t, uint64(1), senderAcc.Nonce)

	receiverAcc := bc.StateTrie.GetAccount(receiver)
	assert.Equal(t, uint64(10), receiverAcc.Balance) // 5 + 5
}

func TestBlockPersistence(t *testing.T) {
	bc, storage := setupTestBlockchain(t)
	defer cleanupTest(storage)

	// Create and add a new block
	tx := Transaction{
		From:   common.HexToAddress("0x100000000000000000000000000000000000000a"),
		To:     common.HexToAddress("0x100000000000000000000000000000000000000b"),
		Amount: 5,
		Nonce:  0,
	}

	latestHash := bc.GetLatestHash()
	prevBlock, err := storage.GetBlock(latestHash)
	assert.NoError(t, err)

	newBlock := CreateBlock([]Transaction{tx}, prevBlock)
	success := bc.AddBlock(newBlock)
	assert.True(t, success)

	// Verify block was stored
	storedBlock, err := storage.GetBlock(newBlock.Hash)
	assert.NoError(t, err)
	assert.Equal(t, newBlock.Hash, storedBlock.Hash)
	assert.Equal(t, newBlock.Index, storedBlock.Index)
}

func TestInvalidTransactions(t *testing.T) {
	bc, storage := setupTestBlockchain(t)
	defer cleanupTest(storage)

	// Test transaction with insufficient balance
	tx := Transaction{
		From:   common.HexToAddress("0x100000000000000000000000000000000000000a"),
		To:     common.HexToAddress("0x100000000000000000000000000000000000000b"),
		Amount: 20, // More than available balance
		Nonce:  0,
	}

	latestHash := bc.GetLatestHash()
	prevBlock, err := storage.GetBlock(latestHash)
	assert.NoError(t, err)

	newBlock := CreateBlock([]Transaction{tx}, prevBlock)
	success := bc.AddBlock(newBlock)
	assert.False(t, success) // Should fail due to insufficient balance

	// Test transaction with invalid nonce
	tx = Transaction{
		From:   common.HexToAddress("0x100000000000000000000000000000000000000a"),
		To:     common.HexToAddress("0x100000000000000000000000000000000000000b"),
		Amount: 5,
		Nonce:  1, // Invalid nonce (should be 0)
	}

	newBlock = CreateBlock([]Transaction{tx}, prevBlock)
	success = bc.AddBlock(newBlock)
	assert.False(t, success) // Should fail due to invalid nonce
}

func TestMultipleTransactions(t *testing.T) {
	bc, storage := setupTestBlockchain(t)
	defer cleanupTest(storage)

	sender := common.HexToAddress("0x100000000000000000000000000000000000000a")
	receiver := common.HexToAddress("0x100000000000000000000000000000000000000b")

	// Create multiple transactions
	txs := []Transaction{
		{From: sender, To: receiver, Amount: 3, Nonce: 0},
		{From: sender, To: receiver, Amount: 2, Nonce: 1},
	}

	latestHash := bc.GetLatestHash()
	prevBlock, err := storage.GetBlock(latestHash)
	assert.NoError(t, err)

	newBlock := CreateBlock(txs, prevBlock)
	success := bc.AddBlock(newBlock)
	assert.True(t, success)

	// Verify final balances
	senderAcc := bc.StateTrie.GetAccount(sender)
	assert.Equal(t, uint64(5), senderAcc.Balance) // 10 - 3 - 2
	assert.Equal(t, uint64(2), senderAcc.Nonce)

	receiverAcc := bc.StateTrie.GetAccount(receiver)
	assert.Equal(t, uint64(10), receiverAcc.Balance) // 5 + 3 + 2
	assert.Equal(t, uint64(0), receiverAcc.Nonce)
}
