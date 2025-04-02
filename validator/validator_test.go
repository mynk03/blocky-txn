package validator

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/transaction"
	"blockchain-simulator/wallet"
	"os"
	"testing"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

const (
	user1     = "0x100000100000000000000000000000000000001a"
	user2     = "0x100000100000000000000000000000000000000d"
	ext_user1 = "0x1100001000000000000000000000000000000001"
	ext_user2 = "0x1110001000000000000000000000000000000009"
	user3     = "0x1000001000000000000000000000000000000010"
	real_user = "0xfbB9295b7Cc91219c67cd2F6f2dec9891949769b"
)

type ValidatorTestSuite struct {
	suite.Suite
	storage1       *blockchain.LevelDBStorage
	storage2       *blockchain.LevelDBStorage
	storage3       *blockchain.LevelDBStorage
	blockchain1    *blockchain.Blockchain
	blockchain2    *blockchain.Blockchain
	tp1            *transaction.TransactionPool
	tp2            *transaction.TransactionPool
	tp3            *transaction.TransactionPool
	validator1     *Validator
	validator2     *Validator
	user1Wallet    *wallet.MockWallet
	user2Wallet    *wallet.MockWallet
	user3Wallet    *wallet.MockWallet
	extUser1Wallet *wallet.MockWallet
	extUser2Wallet *wallet.MockWallet
	realUserWallet *wallet.MockWallet
}

func (suite *ValidatorTestSuite) SetupTest() {
	// Create temporary directories for test databases
	chaindata1Path := "testdata/chaindata1"
	chaindata2Path := "testdata/chaindata2"
	chaindata3Path := "testdata/chaindata3"
	os.MkdirAll(chaindata1Path, 0755)
	os.MkdirAll(chaindata2Path, 0755)
	os.MkdirAll(chaindata3Path, 0755)

	// Initialize storages
	var err error
	suite.storage1, err = blockchain.NewLevelDBStorage(chaindata1Path)
	suite.NoError(err)
	suite.storage2, err = blockchain.NewLevelDBStorage(chaindata2Path)
	suite.NoError(err)
	suite.storage3, err = blockchain.NewLevelDBStorage(chaindata3Path)
	suite.NoError(err)

	// Initialize transaction pools
	suite.tp1 = transaction.NewTransactionPool()
	suite.tp2 = transaction.NewTransactionPool()
	suite.tp3 = transaction.NewTransactionPool()

	// Create wallets for testing
	var err2 error

	// Create user1 wallet
	suite.user1Wallet, err2 = wallet.NewMockWallet()
	suite.NoError(err2)

	// Create user2 wallet
	suite.user2Wallet, err2 = wallet.NewMockWallet()
	suite.NoError(err2)

	// Create user3 wallet
	suite.user3Wallet, err2 = wallet.NewMockWallet()
	suite.NoError(err2)

	// Create external user1 wallet
	suite.extUser1Wallet, err2 = wallet.NewMockWallet()
	suite.NoError(err2)

	// Create external user2 wallet
	suite.extUser2Wallet, err2 = wallet.NewMockWallet()
	suite.NoError(err2)

	// Create real user wallet
	suite.realUserWallet, err2 = wallet.NewMockWallet()
	suite.NoError(err2)

	// Create two blockchains with different accounts
	// Use actual wallet addresses instead of hardcoded ones
	accountAddrs := []string{
		suite.user1Wallet.GetAddress().Hex(),
		suite.user2Wallet.GetAddress().Hex(),
	}
	amounts := []uint64{10, 5}

	suite.blockchain1 = blockchain.NewBlockchain(suite.storage1, accountAddrs, amounts)
	suite.blockchain2 = blockchain.NewBlockchain(suite.storage2, accountAddrs, amounts)

	// Create two validators using wallet addresses
	suite.validator1 = NewValidator(suite.user1Wallet.GetAddress(), suite.tp1, suite.blockchain1)
	suite.validator2 = NewValidator(suite.user2Wallet.GetAddress(), suite.tp2, suite.blockchain2)
}

func (suite *ValidatorTestSuite) TearDownTest() {
	suite.storage1.Close()
	suite.storage2.Close()

	os.RemoveAll("./testdata")
}

// Helper function to create and sign a transaction
func (suite *ValidatorTestSuite) createSignedTransaction(wallet *wallet.MockWallet, to ethcommon.Address, amount uint64, nonce uint64, blockNumber uint32) transaction.Transaction {
	tx := transaction.Transaction{
		From:        wallet.GetAddress(),
		To:          to,
		Amount:      amount,
		Nonce:       nonce,
		BlockNumber: blockNumber,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	// Sign the transaction
	txHash := ethcommon.HexToHash(tx.TransactionHash)
	signature, err := wallet.SignTransaction(txHash)
	suite.NoError(err)
	tx.Signature = signature

	return tx
}

func TestValidatorTestSuite(t *testing.T) {
	suite.Run(t, new(ValidatorTestSuite))
}

func (suite *ValidatorTestSuite) TestValidatorBlockProposalAndValidation() {
	sender, err := suite.blockchain1.StateTrie.GetAccount(suite.user1Wallet.GetAddress())
	suite.NoError(err)
	senderNonce := sender.Nonce

	// Create and sign a transaction using user1's wallet
	tx := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		2,
		senderNonce,
		uint32(suite.blockchain1.LastBlockNumber)+1,
	)

	// Add transaction to pool
	suite.validator1.AddTransaction(tx)

	// Validator1 proposes a block
	proposedBlock := suite.validator1.ProposeNewBlock()

	// Validator2 validates the block
	isValid := suite.validator2.ValidateBlock(proposedBlock)
	suite.True(isValid)

	// Add block to both blockchains
	success1, err1 := suite.blockchain1.AddBlock(proposedBlock)
	success2, err2 := suite.blockchain2.AddBlock(proposedBlock)

	suite.NoError(err1)
	suite.NoError(err2)
	suite.True(success1)
	suite.True(success2)

	// Verify balances after transaction
	senderAcc1, _ := suite.blockchain1.StateTrie.GetAccount(suite.user1Wallet.GetAddress())
	receiverAcc1, _ := suite.blockchain1.StateTrie.GetAccount(suite.user2Wallet.GetAddress())

	suite.Equal(uint64(8), senderAcc1.Balance)   // 10 - 2
	suite.Equal(uint64(7), receiverAcc1.Balance) // 5 + 2
}

func (suite *ValidatorTestSuite) TestAddTransactionValidationFailure() {
	sender, err := suite.blockchain1.StateTrie.GetAccount(suite.user1Wallet.GetAddress())
	suite.NoError(err)
	senderNonce := sender.Nonce

	// Create an invalid transaction (amount exceeds balance)
	tx := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		20, // Amount greater than balance
		senderNonce+4,
		uint32(suite.blockchain1.LastBlockNumber)+1,
	)

	// Attempt to add invalid transaction
	err = suite.validator1.AddTransaction(tx)
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
	isValid := suite.validator1.ValidateBlock(block)
	suite.False(isValid)
}

func (suite *ValidatorTestSuite) TestValidateBlockInvalidIndex() {
	// Create a block with invalid index
	block := blockchain.Block{
		Index:     suite.blockchain1.LastBlockNumber, // Same as last block number
		PrevHash:  "",
		Timestamp: time.Now().UTC().String(),
	}
	block.Hash = blockchain.CalculateBlockHash(block)

	// Attempt to validate block
	isValid := suite.validator1.ValidateBlock(block)
	suite.False(isValid)
}

func (suite *ValidatorTestSuite) TestValidateBlockInvalidStateRoot() {
	// Create a transaction
	tx := transaction.Transaction{
		From:        ethcommon.HexToAddress(user1),
		To:          ethcommon.HexToAddress(user2),
		Amount:      2,
		Nonce:       1,
		BlockNumber: uint32(suite.blockchain1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	// Create a block with the transaction
	block := blockchain.Block{
		Index:        suite.blockchain1.LastBlockNumber + 1,
		PrevHash:     suite.blockchain1.GetLatestBlock().Hash,
		Transactions: []transaction.Transaction{tx},
		Timestamp:    time.Now().UTC().String(),
	}

	// Process block on a temporary state trie
	tempStateTrie := suite.blockchain1.StateTrie.Copy()
	blockchain.ProcessBlock(block, tempStateTrie)
	block.StateRoot = tempStateTrie.RootHash()

	// Modify the state root to make it invalid
	block.StateRoot = "invalid_hash"

	// Attempt to validate block
	isValid := suite.validator1.ValidateBlock(block)
	suite.False(isValid)
}

// New test cases for improved coverage

func (suite *ValidatorTestSuite) TestAddTransactionWithInvalidSender() {
	// Create a transaction with invalid sender address
	tx := transaction.Transaction{
		From:        ethcommon.Address{}, // Empty address
		To:          ethcommon.HexToAddress(user2),
		Amount:      2,
		Nonce:       1,
		BlockNumber: uint32(suite.blockchain1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	err := suite.validator1.AddTransaction(tx)
	suite.Error(err)
}

func (suite *ValidatorTestSuite) TestAddTransactionWithInvalidRecipient() {
	// Create a transaction with invalid recipient address
	tx := transaction.Transaction{
		From:        ethcommon.HexToAddress(user1),
		To:          ethcommon.Address{}, // Empty address
		Amount:      2,
		Nonce:       1,
		BlockNumber: uint32(suite.blockchain1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	err := suite.validator1.AddTransaction(tx)
	suite.Error(err)
}

func (suite *ValidatorTestSuite) TestAddTransactionWithInvalidBlockNumber() {
	// Create a transaction with invalid block number
	tx := transaction.Transaction{
		From:        ethcommon.HexToAddress(user1),
		To:          ethcommon.HexToAddress(user2),
		Amount:      2,
		Nonce:       1,
		BlockNumber: 0, // Invalid block number
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	err := suite.validator1.AddTransaction(tx)
	suite.Error(err)
}

func (suite *ValidatorTestSuite) TestProposeNewBlockWithEmptyPool() {
	// Propose a block with empty transaction pool
	block := suite.validator1.ProposeNewBlock()
	suite.NotNil(block)
	suite.Equal(0, len(block.Transactions))
}

func (suite *ValidatorTestSuite) TestValidateBlockWithInvalidTransactions() {
	// Create a block with invalid transaction
	tx := transaction.Transaction{
		From:        ethcommon.HexToAddress(user1),
		To:          ethcommon.HexToAddress(user2),
		Amount:      20, // Amount greater than balance
		Nonce:       1,
		BlockNumber: uint32(suite.blockchain1.LastBlockNumber) + 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx.TransactionHash = tx.GenerateHash()

	block := blockchain.Block{
		Index:        suite.blockchain1.LastBlockNumber + 1,
		PrevHash:     suite.blockchain1.GetLatestBlock().Hash,
		Transactions: []transaction.Transaction{tx},
		Timestamp:    time.Now().UTC().String(),
	}

	isValid := suite.validator1.ValidateBlock(block)
	suite.False(isValid)
}

func (suite *ValidatorTestSuite) TestValidateBlockWithSameHash() {
	// Create a block with same hash as previous hash
	prevBlock := suite.blockchain1.GetLatestBlock()
	block := blockchain.Block{
		Index:     suite.blockchain1.LastBlockNumber + 1,
		PrevHash:  prevBlock.Hash, // Same as previous hash
		Timestamp: time.Now().UTC().String(),
	}
	block.Hash = prevBlock.Hash // Same hash as previous block

	isValid := suite.validator1.ValidateBlock(block)
	suite.False(isValid)
}

func (suite *ValidatorTestSuite) TestMultipleTransactionsInBlock() {
	user1Account, _ := suite.blockchain1.StateTrie.GetAccount(suite.user1Wallet.GetAddress())
	user1Nonce := user1Account.Nonce

	user2Account, _ := suite.blockchain1.StateTrie.GetAccount(suite.user2Wallet.GetAddress())
	user2Nonce := user2Account.Nonce

	// Create and sign multiple transactions
	tx1 := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		2,
		user1Nonce,
		uint32(suite.blockchain1.LastBlockNumber)+1,
	)

	tx2 := suite.createSignedTransaction(
		suite.user2Wallet,
		suite.user1Wallet.GetAddress(),
		1,
		user2Nonce,
		uint32(suite.blockchain1.LastBlockNumber)+1,
	)

	// Add transactions to pool
	suite.validator1.AddTransaction(tx1)
	suite.validator1.AddTransaction(tx2)

	// Propose and validate block
	block := suite.validator1.ProposeNewBlock()
	isValid := suite.validator2.ValidateBlock(block)
	suite.True(isValid)

	// Add block to blockchain
	success, err := suite.blockchain1.AddBlock(block)
	suite.NoError(err)
	suite.True(success)

	// Verify final balances
	senderAcc1, _ := suite.blockchain1.StateTrie.GetAccount(suite.user1Wallet.GetAddress())
	senderAcc2, _ := suite.blockchain1.StateTrie.GetAccount(suite.user2Wallet.GetAddress())
	suite.Equal(uint64(9), senderAcc1.Balance) // 10 - 2 + 1
	suite.Equal(uint64(6), senderAcc2.Balance) // 5 + 2 - 1
}

func (suite *ValidatorTestSuite) TestValidatorErrorLogging() {
	// Create a transaction with invalid amount (greater than balance)
	tx := suite.createSignedTransaction(
		suite.user1Wallet,
		suite.user2Wallet.GetAddress(),
		20, // Amount greater than balance
		1,
		uint32(suite.blockchain1.LastBlockNumber)+1,
	)

	// Capture logrus output
	var logOutput []byte
	logrus.SetOutput(&logCapture{output: &logOutput})

	// Attempt to add invalid transaction
	err := suite.validator1.AddTransaction(tx)
	suite.Error(err)

	// Verify error logs
	logString := string(logOutput)
	suite.Contains(logString, "Transaction validation failed")
	suite.Contains(logString, "insufficient funds")
}

// logCapture implements io.Writer to capture logrus output
type logCapture struct {
	output *[]byte
}

func (l *logCapture) Write(p []byte) (n int, err error) {
	*l.output = append(*l.output, p...)
	return len(p), nil
}
