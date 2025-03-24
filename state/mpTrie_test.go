package state

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

type MptTrieTestSuite struct {
	suite.Suite
	trie *MptTrie
}

func (suite *MptTrieTestSuite) SetupTest() {
	suite.trie = NewMptTrie()
}

func TestMptTrieSuite(t *testing.T) {
	suite.Run(t, new(MptTrieTestSuite))
}

func (suite *MptTrieTestSuite) TestPutAndGetAccount() {
	// Create test account
	account := &Account{
		Balance: 1000,
		Nonce:   5,
	}

	// Create test address
	address := common.HexToAddress(user1)

	// Test Put
	err := suite.trie.PutAccount(address, account)
	suite.NoError(err)

	// Test Get
	retrievedAccount, err := suite.trie.GetAccount(address)
	suite.NoError(err)
	suite.NotNil(retrievedAccount)
	suite.Equal(account.Balance, retrievedAccount.Balance)
	suite.Equal(account.Nonce, retrievedAccount.Nonce)
}

func (suite *MptTrieTestSuite) TestGetNonExistentAccount() {
	address := common.HexToAddress(user2)
	account, err := suite.trie.GetAccount(address)
	suite.EqualError(err, "item not found")
	suite.Nil(account)
}

func (suite *MptTrieTestSuite) TestMultipleAccounts() {
	// Create multiple test accounts
	accounts := []*Account{
		{Balance: 1000, Nonce: 5},
		{Balance: 2000, Nonce: 10},
		{Balance: 3000, Nonce: 15},
	}

	addresses := []common.Address{
		common.HexToAddress(user1),
		common.HexToAddress(user2),
		common.HexToAddress(user3),
	}

	// Store all accounts
	for i, account := range accounts {
		err := suite.trie.PutAccount(addresses[i], account)
		suite.NoError(err)
	}

	// Retrieve and verify all accounts
	for i, address := range addresses {
		retrievedAccount, err := suite.trie.GetAccount(address)
		suite.NoError(err)
		suite.NotNil(retrievedAccount)
		suite.Equal(accounts[i].Balance, retrievedAccount.Balance)
		suite.Equal(accounts[i].Nonce, retrievedAccount.Nonce)
	}
}

func (suite *MptTrieTestSuite) TestConstAddressesAndUpdates() {
	// Map of test addresses
	addresses := map[string]common.Address{
		"user1":     common.HexToAddress(user1),
		"user2":     common.HexToAddress(user2),
		"ext_user1": common.HexToAddress(ext_user1),
		"ext_user2": common.HexToAddress(ext_user2),
		"user3":     common.HexToAddress(user3),
		"real_user": common.HexToAddress(real_user),
	}

	// Initial accounts
	initialAccounts := map[string]*Account{
		"user1":     {Balance: 1000, Nonce: 1},
		"user2":     {Balance: 2000, Nonce: 2},
		"ext_user1": {Balance: 3000, Nonce: 3},
		"ext_user2": {Balance: 4000, Nonce: 4},
		"user3":     {Balance: 5000, Nonce: 5},
		"real_user": {Balance: 6000, Nonce: 6},
	}

	// Store initial accounts
	for name, addr := range addresses {
		err := suite.trie.PutAccount(addr, initialAccounts[name])
		suite.NoError(err, "Failed to store initial account for %s", name)
	}

	// Verify initial storage
	for name, addr := range addresses {
		retrieved, err := suite.trie.GetAccount(addr)
		suite.NoError(err, "Failed to retrieve account for %s", name)
		suite.NotNil(retrieved, "Retrieved account is nil for %s", name)
		suite.Equal(initialAccounts[name].Balance, retrieved.Balance,
			"Wrong initial balance for %s", name)
		suite.Equal(initialAccounts[name].Nonce, retrieved.Nonce,
			"Wrong initial nonce for %s", name)
	}

	// Update accounts multiple times
	updates := []map[string]*Account{
		{
			"user1":     {Balance: 1500, Nonce: 7},
			"ext_user2": {Balance: 4500, Nonce: 8},
			"real_user": {Balance: 6500, Nonce: 9},
		},
		{
			"user2":     {Balance: 2500, Nonce: 10},
			"ext_user1": {Balance: 3500, Nonce: 11},
			"user3":     {Balance: 5500, Nonce: 12},
		},
	}

	// Perform updates
	for i, updateSet := range updates {
		for name, newAccount := range updateSet {
			err := suite.trie.PutAccount(addresses[name], newAccount)
			suite.NoError(err, "Failed update %d for %s", i+1, name)

			// Verify update immediately
			retrieved, err := suite.trie.GetAccount(addresses[name])
			suite.NoError(err, "Failed to retrieve updated account %d for %s", i+1, name)
			suite.NotNil(retrieved, "Retrieved updated account is nil for %s", name)
			suite.Equal(newAccount.Balance, retrieved.Balance,
				"Wrong updated balance for %s after update %d", name, i+1)
			suite.Equal(newAccount.Nonce, retrieved.Nonce,
				"Wrong updated nonce for %s after update %d", name, i+1)
		}
	}

	// Final verification of all accounts
	expectedFinal := make(map[string]*Account)
	for name, initial := range initialAccounts {
		expectedFinal[name] = initial
	}
	// Apply all updates to get expected final state
	for _, updateSet := range updates {
		for name, update := range updateSet {
			expectedFinal[name] = update
		}
	}

	// Verify final state
	for name, addr := range addresses {
		retrieved, err := suite.trie.GetAccount(addr)
		suite.NoError(err, "Failed to retrieve final account for %s", name)
		suite.NotNil(retrieved, "Retrieved final account is nil for %s", name)
		suite.Equal(expectedFinal[name].Balance, retrieved.Balance,
			"Wrong final balance for %s", name)
		suite.Equal(expectedFinal[name].Nonce, retrieved.Nonce,
			"Wrong final nonce for %s", name)
	}

	err := suite.trie.PutAccount(common.HexToAddress(user1), &Account{
		Balance: 1500,
		Nonce:   7,
	})
	suite.NoError(err, "Failed to update User1 account")

	retrieved, err := suite.trie.GetAccount(common.HexToAddress(user1))
	suite.NoError(err, "Failed to retrieve updated User1 account")
	suite.NotNil(retrieved, "Retrieved updated User1 account is nil")

	suite.Equal(uint64(1500), retrieved.Balance, "Wrong updated balance for User1")
	suite.Equal(uint64(7), retrieved.Nonce, "Wrong updated nonce for User1")

	// verify the update
	retrieved, err = suite.trie.GetAccount(common.HexToAddress(user1))
	suite.NoError(err, "Failed to retrieve updated User1 account")
	suite.NotNil(retrieved, "Retrieved updated User1 account is nil")
	suite.Equal(uint64(1500), retrieved.Balance, "Wrong updated balance for User1")
	suite.Equal(uint64(7), retrieved.Nonce, "Wrong updated nonce for User1")

}
