// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package blockchain

import (
	"blockchain-simulator/internal/state"
	"blockchain-simulator/internal/transaction"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type StateRootTestSuite struct {
	suite.Suite
	trie         *state.MptTrie
	stakeAddress common.Address
}

func (suite *StateRootTestSuite) SetupTest() {
	suite.trie = state.NewMptTrie()
	suite.stakeAddress = common.HexToAddress("0x1234567890123456789012345678901234567890")
}

func TestStateRootTestSuite(t *testing.T) {
	suite.Run(t, new(StateRootTestSuite))
}

// logCapture implements io.Writer to capture logrus output
type logCapture struct {
	output *[]byte
}

func (l *logCapture) Write(p []byte) (n int, err error) {
	*l.output = append(*l.output, p...)
	return len(p), nil
}

func (suite *StateRootTestSuite) TestProcessBlockWithValidAccounts() {
	// Create test accounts
	sender := &state.Account{
		Balance: 1000,
		Stake:   0,
		Nonce:   0,
	}
	receiver := &state.Account{
		Balance: 500,
		Stake:   0,
		Nonce:   0,
	}

	// Create test addresses
	senderAddr := common.HexToAddress("0x1234567890123456789012345678900987654321")
	receiverAddr := common.HexToAddress("0x0987654321098765432109876543210987654321")

	// Store accounts in trie
	err := suite.trie.PutAccount(senderAddr, sender)
	suite.NoError(err)
	err = suite.trie.PutAccount(receiverAddr, receiver)
	suite.NoError(err)

	// Create a test block with a transaction
	block := Block{
		Index: 1,
		Transactions: []transaction.Transaction{
			{
				Sender:   senderAddr,
				Receiver: receiverAddr,
				Amount:   100,
			},
			{
				Sender:   senderAddr,
				Receiver: suite.stakeAddress,
				Amount:   200,
			},
		},
	}

	// Capture logrus output
	var logOutput []byte
	logrus.SetOutput(&logCapture{output: &logOutput})

	// Process the block
	ProcessBlock(block, suite.trie, suite.stakeAddress)

	// Verify no error logs were generated
	logString := string(logOutput)
	suite.NotContains(logString, "Error in Retreiving sender account")
	suite.NotContains(logString, "Error Retreiving receiver account")

	// Verify account updates
	updatedSender, err := suite.trie.GetAccount(senderAddr)
	suite.NoError(err)
	suite.Equal(uint64(700), updatedSender.Balance)
	suite.Equal(uint64(200), updatedSender.Stake)
	suite.Equal(uint64(2), updatedSender.Nonce)

	stakeAddressAccount, err := suite.trie.GetAccount(suite.stakeAddress)
	suite.NoError(err)
	suite.Equal(uint64(200), stakeAddressAccount.Balance)

	updatedReceiver, err := suite.trie.GetAccount(receiverAddr)
	suite.NoError(err)
	suite.Equal(uint64(600), updatedReceiver.Balance)
}

// TestInitializeStorage tests the InitializeStorage function
func (suite *StateRootTestSuite) TestInitializeStorage() {

	dbPath := "./chaindata"
	// Call InitializeStorage with the test database path
	storage := InitializeStorage()

	// Ensure the LevelDB instance is initialized and no error occurred
	suite.NotNil(storage)
	suite.NotNil(storage.db)

	// Optionally verify that the database was created by checking the files
	_, err := os.Stat(dbPath)
	suite.NoError(err, "The database should have been created in the specified path")

	// close the storage
	storage.Close()
	// remove the database
	os.RemoveAll(dbPath)
}

// TestInitializeStorage tests the InitializeStorage function
func (suite *StateRootTestSuite) TestInitializeStorageWithInvalidPath() {

	dbPath := ""
	// Call InitializeStorage with the test database path
	storage := InitializeStorage()

	// Ensure the LevelDB instance is initialized and no error occurred
	suite.NotNil(storage)
	suite.NotNil(storage.db)

	// Optionally verify that the database was created by checking the files
	_, err := os.Stat(dbPath)
	suite.Error(err)
	storage.Close()
	os.RemoveAll(dbPath)
	os.RemoveAll("./chaindata")
}
