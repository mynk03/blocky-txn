package transactions

import (
	"blockchain-simulator/crypto"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

type TransactionTestSuite struct {
	suite.Suite
	senderWallet   *crypto.Wallet
	receiverWallet *crypto.Wallet
	thirdWallet    *crypto.Wallet
}

func (suite *TransactionTestSuite) SetupTest() {
	// Generate mnemonics and create wallets
	senderMnemonic, err := crypto.GenerateMnemonic()
	suite.NoError(err)
	suite.senderWallet, err = crypto.GetWallet(senderMnemonic)
	suite.NoError(err)

	receiverMnemonic, err := crypto.GenerateMnemonic()
	suite.NoError(err)
	suite.receiverWallet, err = crypto.GetWallet(receiverMnemonic)
	suite.NoError(err)

	thirdMnemonic, err := crypto.GenerateMnemonic()
	suite.NoError(err)
	suite.thirdWallet, err = crypto.GetWallet(thirdMnemonic)
	suite.NoError(err)
}

// signTransaction is a helper method to sign a transaction using the provided wallet
func (suite *TransactionTestSuite) signTransaction(tx *Transaction, wallet *crypto.Wallet) error {
	// Generate transaction hash
	tx.TransactionHash = tx.GenerateHash()

	// Convert hash to bytes
	txHash := common.HexToHash(tx.TransactionHash)

	// Sign the hash
	signature, err := wallet.SignTransaction(txHash)
	if err != nil {
		return err
	}

	tx.Signature = signature
	return nil
}

func TestTransactionTestSuite(t *testing.T) {
	suite.Run(t, new(TransactionTestSuite))
}
func (suite *TransactionTestSuite) TestTransactionSigning() {
	// Create a test transaction
	tx := Transaction{
		From:        suite.senderWallet.Address,
		To:          suite.receiverWallet.Address,
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}

	// Test signing
	err := suite.signTransaction(&tx, suite.senderWallet)
	suite.NoError(err)
	suite.NotNil(tx.Signature)

	// Test verification
	isValid := tx.Verify()
	suite.True(isValid)

	// Test verification with wrong address
	tx.From = suite.thirdWallet.Address
	isValid = tx.Verify()
	suite.False(isValid)
}

func (suite *TransactionTestSuite) TestTransactionValidationWithSignature() {
	// Create a test transaction
	tx := Transaction{
		From:        suite.senderWallet.Address,
		To:          suite.receiverWallet.Address,
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}

	// Test validation without signature
	valid, err := tx.Validate()
	suite.True(valid)
	suite.NoError(err)

	// Sign the transaction
	err = suite.signTransaction(&tx, suite.senderWallet)
	suite.NoError(err)

	// Test validation with signature
	valid, err = tx.Validate()
	suite.True(valid)
	suite.NoError(err)
}

func (suite *TransactionTestSuite) TestTransactionHashGeneration() {
	// Create a test transaction
	tx := Transaction{
		From:        suite.senderWallet.Address,
		To:          suite.receiverWallet.Address,
		Amount:      100,
		Nonce:       1,
		BlockNumber: 1,
		Timestamp:   1234567890,
	}

	// Generate hash
	hash1 := tx.GenerateHash()
	suite.NotEmpty(hash1)

	// Generate hash again - should be the same
	hash2 := tx.GenerateHash()
	suite.Equal(hash1, hash2)

	// Modify transaction and generate new hash - should be different
	tx.Amount = 200
	hash3 := tx.GenerateHash()
	suite.NotEqual(hash1, hash3)
}
