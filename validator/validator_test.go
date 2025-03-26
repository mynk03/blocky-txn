package validator

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/transactions"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

const (
	chaindata1Path = "./testdata/validator1/chaindata"
	chaindata2Path = "./testdata/validator2/chaindata"

	user1     = "0x100000100000000000000000000000000000001a"
	user2     = "0x100000100000000000000000000000000000000d"
	ext_user1 = "0x1100001000000000000000000000000000000001"
	ext_user2 = "0x1110001000000000000000000000000000000009"
	user3     = "0x1000001000000000000000000000000000000010"
	real_user = "0xfbB9295b7Cc91219c67cd2F6f2dec9891949769b"
)

type ValidatorTestSuite struct {
	suite.Suite
	bc1      *blockchain.Blockchain
	bc2      *blockchain.Blockchain
	storage1 blockchain.Storage
	storage2 blockchain.Storage
	tp1      *transactions.TransactionPool
	tp2      *transactions.TransactionPool
	v1       *Validator
	v2       *Validator
}

func (suite *ValidatorTestSuite) SetupTest() {
	// Initialize storage for blockchain and both validators
	suite.storage1, _ = blockchain.NewLevelDBStorage(chaindata1Path)
	suite.storage2, _ = blockchain.NewLevelDBStorage(chaindata2Path)

	// Initialize transaction pools
	suite.tp1 = transactions.NewTransactionPool()
	suite.tp2 = transactions.NewTransactionPool()

	// Create two blockchains with different accounts
	accountAddrs := []string{user1, user2}
	amounts := []uint64{10, 5}

	suite.bc1 = blockchain.NewBlockchain(suite.storage1, accountAddrs, amounts)
	suite.bc2 = blockchain.NewBlockchain(suite.storage2, accountAddrs, amounts)

	// Create two validators
	suite.v1 = NewValidator(common.HexToAddress(user1), suite.tp1, suite.bc1)
	suite.v2 = NewValidator(common.HexToAddress(user2), suite.tp2, suite.bc2)
}

func (suite *ValidatorTestSuite) TearDownTest() {
	suite.storage1.Close()
	suite.storage2.Close()

	os.RemoveAll("./testdata")
}

func TestValidatorTestSuite(t *testing.T) {
	suite.Run(t, new(ValidatorTestSuite))
}

func (suite *ValidatorTestSuite) TestValidatorBlockProposalAndValidation() {
	// Create a transaction
	tx := transactions.Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      2,
		Nonce:       1,
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	// Add transaction to pool
	suite.v1.AddTransaction(tx)

	// Validator1 proposes a block
	proposedBlock := suite.v1.ProposeNewBlock()

	fmt.Println("Here Root Hash of validator1 chain", suite.bc1.StateTrie.RootHash())

	// Validator2 validates the block
	isValid := suite.v2.ValidateBlock(proposedBlock)
	suite.True(isValid)

	// Add block to both blockchains
	success1, err1 := suite.bc1.AddBlock(proposedBlock)
	success2, err2 := suite.bc2.AddBlock(proposedBlock)

	suite.NoError(err1)
	suite.NoError(err2)
	suite.True(success1)
	suite.True(success2)

	// Verify balances after transaction
	senderAcc1, _ := suite.bc1.StateTrie.GetAccount(common.HexToAddress(user1))
	receiverAcc1, _ := suite.bc1.StateTrie.GetAccount(common.HexToAddress(user2))

	suite.Equal(uint64(8), senderAcc1.Balance)   // 10 - 2
	suite.Equal(uint64(7), receiverAcc1.Balance) // 5 + 2
}

func (suite *ValidatorTestSuite) TestAddTransactionValidationFailure() {
	// Create an invalid transaction (amount exceeds balance)
	tx := transactions.Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      20, // Amount greater than balance
		Nonce:       1,
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	// Attempt to add invalid transaction
	err := suite.v1.AddTransaction(tx)
	suite.Error(err)
}

func (suite *ValidatorTestSuite) TestValidateBlockInvalidPrevHash() {
	// Create a block with invalid previous hash
	block := blockchain.Block{
		Index:     1,
		PrevHash:  "", // Empty hash
		Timestamp: time.Now().UTC().String(),
	}
	block.Hash = blockchain.CalculateBlockHash(block)

	// Attempt to validate block
	isValid := suite.v1.ValidateBlock(block)
	suite.False(isValid)
}

func (suite *ValidatorTestSuite) TestValidateBlockInvalidIndex() {
	// Create a block with invalid index
	block := blockchain.Block{
		Index:     suite.bc1.LastBlockNumber, // Same as last block number
		PrevHash:  "",
		Timestamp: time.Now().UTC().String(),
	}
	block.Hash = blockchain.CalculateBlockHash(block)

	// Attempt to validate block
	isValid := suite.v1.ValidateBlock(block)
	suite.False(isValid)
}

func (suite *ValidatorTestSuite) TestValidateBlockInvalidStateRoot() {
	// Create a transaction
	tx := transactions.Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      2,
		Nonce:       1,
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	// Create a block with the transaction
	block := blockchain.Block{
		Index:        suite.bc1.LastBlockNumber + 1,
		PrevHash:     suite.bc1.GetLatestBlock().Hash,
		Transactions: []transactions.Transaction{tx},
		Timestamp:    time.Now().UTC().String(),
	}

	// Process block on a temporary state trie
	tempStateTrie := suite.bc1.StateTrie.Copy()
	blockchain.ProcessBlock(block, tempStateTrie)
	block.StateRoot = tempStateTrie.RootHash()

	// Modify the state root to make it invalid
	block.StateRoot = "invalid_hash"

	// Attempt to validate block
	isValid := suite.v1.ValidateBlock(block)
	suite.False(isValid)
}

// New test cases for improved coverage

func (suite *ValidatorTestSuite) TestAddTransactionWithInvalidSender() {
	// Create a transaction with invalid sender address
	tx := transactions.Transaction{
		From:        common.Address{}, // Empty address
		To:          common.HexToAddress(user2),
		Amount:      2,
		Nonce:       1,
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	err := suite.v1.AddTransaction(tx)
	suite.Error(err)
}

func (suite *ValidatorTestSuite) TestAddTransactionWithInvalidRecipient() {
	// Create a transaction with invalid recipient address
	tx := transactions.Transaction{
		From:        common.HexToAddress(user1),
		To:          common.Address{}, // Empty address
		Amount:      2,
		Nonce:       1,
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	err := suite.v1.AddTransaction(tx)
	suite.Error(err)
}

func (suite *ValidatorTestSuite) TestAddTransactionWithInvalidNonce() {
	// Create a transaction with invalid nonce
	tx := transactions.Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      2,
		Nonce:       0, // Invalid nonce
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	err := suite.v1.AddTransaction(tx)
	suite.Error(err)
}

func (suite *ValidatorTestSuite) TestAddTransactionWithInvalidBlockNumber() {
	// Create a transaction with invalid block number
	tx := transactions.Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      2,
		Nonce:       1,
		BlockNumber: 0, // Invalid block number
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	err := suite.v1.AddTransaction(tx)
	suite.Error(err)
}

func (suite *ValidatorTestSuite) TestProposeNewBlockWithEmptyPool() {
	// Propose a block with empty transaction pool
	block := suite.v1.ProposeNewBlock()
	suite.NotNil(block)
	suite.Equal(0, len(block.Transactions))
}

func (suite *ValidatorTestSuite) TestValidateBlockWithInvalidTransactions() {
	// Create a block with invalid transaction
	tx := transactions.Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      20, // Amount greater than balance
		Nonce:       1,
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	block := blockchain.Block{
		Index:        suite.bc1.LastBlockNumber + 1,
		PrevHash:     suite.bc1.GetLatestBlock().Hash,
		Transactions: []transactions.Transaction{tx},
		Timestamp:    time.Now().UTC().String(),
	}

	isValid := suite.v1.ValidateBlock(block)
	suite.False(isValid)
}

func (suite *ValidatorTestSuite) TestValidateBlockWithSameHash() {
	// Create a block with same hash as previous hash
	prevBlock := suite.bc1.GetLatestBlock()
	block := blockchain.Block{
		Index:     suite.bc1.LastBlockNumber + 1,
		PrevHash:  prevBlock.Hash, // Same as previous hash
		Timestamp: time.Now().UTC().String(),
	}
	block.Hash = prevBlock.Hash // Same hash as previous block

	isValid := suite.v1.ValidateBlock(block)
	suite.False(isValid)
}

func (suite *ValidatorTestSuite) TestMultipleTransactionsInBlock() {
	// Create multiple transactions
	tx1 := transactions.Transaction{
		From:        common.HexToAddress(user1),
		To:          common.HexToAddress(user2),
		Amount:      2,
		Nonce:       1,
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx1.TransactionHash = tx1.GenerateHash()

	tx2 := transactions.Transaction{
		From:        common.HexToAddress(user2),
		To:          common.HexToAddress(user1),
		Amount:      1,
		Nonce:       1,
		BlockNumber: uint32(suite.bc1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx2.TransactionHash = tx2.GenerateHash()

	// Add transactions to pool
	suite.v1.AddTransaction(tx1)
	suite.v1.AddTransaction(tx2)

	// Propose and validate block
	block := suite.v1.ProposeNewBlock()
	isValid := suite.v2.ValidateBlock(block)
	suite.True(isValid)

	// Add block to blockchain
	success, err := suite.bc1.AddBlock(block)
	suite.NoError(err)
	suite.True(success)

	// Verify final balances
	senderAcc1, _ := suite.bc1.StateTrie.GetAccount(common.HexToAddress(user1))
	senderAcc2, _ := suite.bc1.StateTrie.GetAccount(common.HexToAddress(user2))
	suite.Equal(uint64(9), senderAcc1.Balance) // 10 - 2 + 1
	suite.Equal(uint64(6), senderAcc2.Balance) // 5 + 2 - 1
}
