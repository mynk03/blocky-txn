package transactions

import (
	"testing"
	"time"

	"blockchain-simulator/wallet"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

type TransactionTestSuite struct {
	suite.Suite
	senderWallet   *wallet.MockWallet
	receiverWallet *wallet.MockWallet
	thirdWallet    *wallet.MockWallet
}

func (suite *TransactionTestSuite) SetupTest() {
	// Create sender wallet
	var err error
	suite.senderWallet, err = wallet.NewMockWallet()
	suite.NoError(err)

	// Create receiver wallet
	suite.receiverWallet, err = wallet.NewMockWallet()
	suite.NoError(err)

	// Create third wallet for testing
	suite.thirdWallet, err = wallet.NewMockWallet()
	suite.NoError(err)
}

func TestTransactionTestSuite(t *testing.T) {
	suite.Run(t, new(TransactionTestSuite))
}

func (suite *TransactionTestSuite) TestTransactionSigning() {
	// Create a test transaction
	tx := Transaction{
		From:        suite.senderWallet.GetAddress(),
		To:          suite.receiverWallet.GetAddress(),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   uint64(time.Now().Unix()),
	}

	// Generate transaction hash
	tx.TransactionHash = tx.GenerateHash()

	// Verify the signature before signing
	isValid, err := tx.Verify()
	suite.Error(err)
	suite.False(isValid)

	// Sign the transaction
	signature, err := suite.senderWallet.SignTransaction(common.HexToHash(tx.TransactionHash))
	suite.NoError(err)
	tx.Signature = signature

	// Verify the signature
	isValid, err = tx.Verify()
	suite.NoError(err)
	suite.True(isValid)
	suite.Equal(suite.senderWallet.GetAddress(), tx.From)

	// Test invalid signature
	tx2 := Transaction{
		From:        suite.thirdWallet.GetAddress(),
		To:          suite.receiverWallet.GetAddress(),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   uint64(time.Now().Unix()),
	}
	tx2.TransactionHash = tx2.GenerateHash()

	// Sign with wrong wallet (sender wallet instead of third wallet)
	signature, err = suite.senderWallet.SignTransaction(common.HexToHash(tx2.TransactionHash))
	suite.NoError(err)
	tx2.Signature = signature

	// Verify should fail because wrong wallet signed
	isValid, err = tx2.Verify()
	suite.NoError(err)
	suite.False(isValid)
}

func (suite *TransactionTestSuite) TestTransactionHash() {
	// Create two identical transactions
	tx1 := Transaction{
		From:        suite.senderWallet.GetAddress(),
		To:          suite.receiverWallet.GetAddress(),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}

	tx2 := Transaction{
		From:        suite.senderWallet.GetAddress(),
		To:          suite.receiverWallet.GetAddress(),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}

	// Generate hashes
	hash1 := tx1.GenerateHash()
	hash2 := tx2.GenerateHash()

	// Hashes should be equal for identical transactions
	suite.Equal(hash1, hash2)

	// Modify tx2 and verify hash changes
	tx2.Amount = 200
	hash2 = tx2.GenerateHash()
	suite.NotEqual(hash1, hash2)
}

func (suite *TransactionTestSuite) TestTransactionSigningError() {
	// Create a test transaction
	tx := Transaction{
		From:        suite.senderWallet.GetAddress(),
		To:          suite.receiverWallet.GetAddress(),
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   uint64(time.Now().Unix()),
	}

	// Generate transaction hash
	tx.TransactionHash = tx.GenerateHash()

	// Create a wallet with nil private key to test error
	invalidWallet := &wallet.MockWallet{} // This will have nil private key

	// Try to sign with invalid wallet
	signature, err := invalidWallet.SignTransaction(common.HexToHash(tx.TransactionHash))
	suite.Error(err)
	suite.Nil(signature)
	suite.Equal("private key is nil", err.Error())
}
