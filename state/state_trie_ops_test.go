package state

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

const (
	// user1      = "0x100000100000000000000000000000000000111a"
	// user2      = "0x100000100000000000000000000000000000111b"
	user1     = "0x100000100000000000000000000000000000000a"
	user2     = "0x100000100000000000000000000000000000000d"
	ext_user1 = "0x1100001000000000000000000000000000000001"
	ext_user2 = "0x1110001000000000000000000000000000000009"
	user3     = "0x1000001000000000000000000000000000000010"
	real_user = "0xfbB9295b7Cc91219c67cd2F6f2dec9891949769b"
)

// Define the test suite
type StateTrieTestSuite struct {
	suite.Suite
	trie *Trie
}

// Setup the test suite
func (suite *StateTrieTestSuite) SetupTest() {
	suite.trie = NewTrie()
}

// Run the test suite
func TestStateTrieTestSuite(t *testing.T) {
	suite.Run(t, new(StateTrieTestSuite))
}

// Test inserting and retrieving an account
func (suite *StateTrieTestSuite) TestInsertAndRetrieveAccount() {
	address := common.HexToAddress(user1)
	account := Account{Balance: 10, Nonce: 0}

	suite.trie.PutAccount(address, &account)
	retrievedAccount := suite.trie.GetAccount(address)

	suite.Equal(account.Balance, retrievedAccount.Balance)
	suite.Equal(account.Nonce, retrievedAccount.Nonce)
}

// Test updating an account
func (suite *StateTrieTestSuite) TestUpdateAccount() {
	address := common.HexToAddress(user1)
	account := Account{Balance: 10, Nonce: 0}

	suite.trie.PutAccount(address, &account)

	// Update account
	updatedAccount := Account{Balance: 120, Nonce: 1}
	suite.trie.PutAccount(address, &updatedAccount)

	retrievedAccount := suite.trie.GetAccount(address)
	suite.Equal(updatedAccount.Balance, retrievedAccount.Balance)
	suite.Equal(updatedAccount.Nonce, retrievedAccount.Nonce)
}

// Test retrieving a non-existent account
func (suite *StateTrieTestSuite) TestRetrieveNonExistentAccount() {
	address := common.HexToAddress(user2) // user2 is not in the trie
	retrievedAccount := suite.trie.GetAccount(address)

	suite.Nil(retrievedAccount)
}

// Test inserting multiple accounts
func (suite *StateTrieTestSuite) TestInsertMultipleAccounts() {
	address1 := common.HexToAddress(user1)
	address2 := common.HexToAddress(user2)
	address3 := common.HexToAddress(ext_user1)
	address4 := common.HexToAddress(ext_user2)
	address5 := common.HexToAddress(user3)
	address6 := common.HexToAddress(real_user)

	// Insert accounts
	suite.trie.PutAccount(address1, &Account{Balance: 10, Nonce: 0})
	suite.trie.PutAccount(address2, &Account{Balance: 20, Nonce: 0})
	suite.trie.PutAccount(address3, &Account{Balance: 30, Nonce: 0})
	suite.trie.PutAccount(address4, &Account{Balance: 40, Nonce: 0})
	suite.trie.PutAccount(address5, &Account{Balance: 50, Nonce: 0})
	suite.trie.PutAccount(address6, &Account{Balance: 60, Nonce: 0})

	// Retrieve and verify accounts
	retrievedAccount1 := suite.trie.GetAccount(address1)
	suite.NotNil(retrievedAccount1) // Ensure the account is not nil
	suite.Equal(uint64(10), retrievedAccount1.Balance)
	suite.Equal(uint64(0), retrievedAccount1.Nonce)

	retrievedAccount2 := suite.trie.GetAccount(address2)
	suite.NotNil(retrievedAccount2) // Ensure the account is not nil
	suite.Equal(uint64(20), retrievedAccount2.Balance)
	suite.Equal(uint64(0), retrievedAccount2.Nonce)

	retrievedAccount3 := suite.trie.GetAccount(address3)
	suite.NotNil(retrievedAccount3) // Ensure the account is not nil
	suite.Equal(uint64(30), retrievedAccount3.Balance)
	suite.Equal(uint64(0), retrievedAccount3.Nonce)

	retrievedAccount4 := suite.trie.GetAccount(address4)
	suite.NotNil(retrievedAccount4) // Ensure the account is not nil
	suite.Equal(uint64(40), retrievedAccount4.Balance)
	suite.Equal(uint64(0), retrievedAccount4.Nonce)

	retrievedAccount5 := suite.trie.GetAccount(address5)
	suite.NotNil(retrievedAccount5) // Ensure the account is not nil
	suite.Equal(uint64(50), retrievedAccount5.Balance)
	suite.Equal(uint64(0), retrievedAccount5.Nonce)

	retrievedAccount6 := suite.trie.GetAccount(address6)
	suite.NotNil(retrievedAccount6) // Ensure the account is not nil
	suite.Equal(uint64(60), retrievedAccount6.Balance)
	suite.Equal(uint64(0), retrievedAccount6.Nonce)

	suite.trie.PutAccount(address6, &Account{Balance: 60, Nonce: 1})
	retrievedAccount6 = suite.trie.GetAccount(address6)
	suite.NotNil(retrievedAccount6) // Ensure the account is not nil
	suite.Equal(uint64(60), retrievedAccount6.Balance)
	suite.Equal(uint64(1), retrievedAccount6.Nonce)
}

func (suite *StateTrieTestSuite) TestTransactionProcessing() {

	senderAddress := common.HexToAddress(user1)
	receiverAddress := common.HexToAddress(ext_user1)

	// initial balances
	suite.trie.PutAccount(senderAddress, &Account{Balance: 10, Nonce: 0})
	suite.trie.PutAccount(receiverAddress, &Account{Balance: 5, Nonce: 0})

	// logs
	senderAcc := suite.trie.GetAccount(senderAddress)
	receiverAcc := suite.trie.GetAccount(receiverAddress)

	// current balances
	senderAccBalance := senderAcc.Balance
	receiverAccBalance := receiverAcc.Balance

	senderAccNonce := senderAcc.Nonce
	suite.trie.PutAccount(senderAddress, &Account{Balance: senderAccBalance - 3, Nonce: senderAccNonce + 1})
	suite.trie.PutAccount(receiverAddress, &Account{Balance: receiverAccBalance + 3, Nonce: 0})

	// Verify account balances after transaction
	senderAcc = suite.trie.GetAccount(senderAddress)
	suite.Equal(uint64(7), senderAcc.Balance) // 10 - 3
	suite.Equal(uint64(1), senderAcc.Nonce)

	receiverAcc = suite.trie.GetAccount(receiverAddress)
	suite.Equal(uint64(8), receiverAcc.Balance) // 5 + 3
}
