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
	mainChainDataPath = "./testdata/main/chaindata"
	chaindata1Path    = "./testdata/validator1/chaindata"
	chaindata2Path    = "./testdata/validator2/chaindata"
	pool1Path         = "./testdata/validator1/test_pool"
	pool2Path         = "./testdata/validator2/test_pool"

	user1     = "0x100000100000000000000000000000000000001a"
	user2     = "0x100000100000000000000000000000000000000d"
	ext_user1 = "0x1100001000000000000000000000000000000001"
	ext_user2 = "0x1110001000000000000000000000000000000009"
	user3     = "0x1000001000000000000000000000000000000010"
	real_user = "0xfbB9295b7Cc91219c67cd2F6f2dec9891949769b"
)

type ValidatorTestSuite struct {
	suite.Suite
	bc          *blockchain.Blockchain
	bc1         *blockchain.Blockchain
	bc2         *blockchain.Blockchain
	mainStorage blockchain.Storage
	storage1    blockchain.Storage
	storage2    blockchain.Storage
	tp1         *transactions.TransactionPool
	tp2         *transactions.TransactionPool
	tp1Storage  transactions.TransactionStorage
	tp2Storage  transactions.TransactionStorage
	v1          *Validator
	v2          *Validator
}

func (suite *ValidatorTestSuite) SetupTest() {
	// Initialize storage for blockchain and both validators
	suite.mainStorage, _ = blockchain.NewLevelDBStorage(mainChainDataPath)

	suite.storage1, _ = blockchain.NewLevelDBStorage(chaindata1Path)
	suite.storage2, _ = blockchain.NewLevelDBStorage(chaindata2Path)

	// Initialize transaction pools
	suite.tp1Storage = transactions.InitializeStorage(pool1Path)
	suite.tp2Storage = transactions.InitializeStorage(pool2Path)
	suite.tp1, _ = transactions.NewTransactionPool(suite.tp1Storage)
	suite.tp2, _ = transactions.NewTransactionPool(suite.tp2Storage)

	// Create two blockchains with different accounts
	accountAddrs := []string{user1, user2}
	amounts := []uint64{10, 5}

	suite.bc = blockchain.NewBlockchain(suite.mainStorage, accountAddrs, amounts)
	suite.bc1 = blockchain.NewBlockchain(suite.storage1, accountAddrs, amounts)
	suite.bc2 = blockchain.NewBlockchain(suite.storage2, accountAddrs, amounts)

	fmt.Println("Here Root Hash of main chain", suite.bc.StateTrie.RootHash())
	fmt.Println("Here Root Hash of validator1 chain", suite.bc1.StateTrie.RootHash())
	fmt.Println("Here Root Hash of validator2 chain", suite.bc2.StateTrie.RootHash())

	// Create two validators
	suite.v1 = NewValidator(common.HexToAddress(user1), suite.tp1, suite.bc1)
	suite.v2 = NewValidator(common.HexToAddress(user2), suite.tp2, suite.bc2)
}

func (suite *ValidatorTestSuite) TearDownTest() {
	suite.mainStorage.Close()

	suite.storage1.Close()
	suite.storage2.Close()
	suite.tp1Storage.Close()
	suite.tp2Storage.Close()

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
		BlockNumber: uint32(suite.bc.LastBlockNumber) + 1,
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
