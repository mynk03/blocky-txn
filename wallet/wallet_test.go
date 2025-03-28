package wallet

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/suite"
)

type WalletTestSuite struct {
	suite.Suite
	wallet  *MockWallet
	wallet2 *MockWallet
}

func (suite *WalletTestSuite) SetupTest() {
	// Create test wallets
	var err error
	suite.wallet, err = NewMockWallet()
	suite.NoError(err)
	suite.NotNil(suite.wallet)

	suite.wallet2, err = NewMockWallet()
	suite.NoError(err)
	suite.NotNil(suite.wallet2)
}

func TestWalletTestSuite(t *testing.T) {
	suite.Run(t, new(WalletTestSuite))
}

func (suite *WalletTestSuite) TestNewMockWallet() {
	// Check that the address is not empty
	suite.NotEqual(common.Address{}, suite.wallet.GetAddress())

	// Check that the private key is not nil
	suite.NotNil(suite.wallet.privateKey)
}

func (suite *WalletTestSuite) TestMockWalletSignTransaction() {
	// Create a test hash to sign
	testHash := crypto.Keccak256Hash([]byte("test message"))

	// Sign the hash
	signature, err := suite.wallet.SignTransaction(testHash)
	suite.NoError(err)
	suite.NotNil(signature)

	// Verify that the signature is valid
	pubkey := suite.wallet.privateKey.Public().(*ecdsa.PublicKey)
	signatureNoRecoverID := signature[:len(signature)-1] // Remove recovery ID
	valid := crypto.VerifySignature(
		crypto.FromECDSAPub(pubkey),
		testHash.Bytes(),
		signatureNoRecoverID,
	)
	suite.True(valid)
}

func (suite *WalletTestSuite) TestMockWalletUniqueness() {
	// Check that wallets have different addresses
	suite.NotEqual(suite.wallet.GetAddress(), suite.wallet2.GetAddress())

	// Check that wallets have different private keys
	suite.NotEqual(suite.wallet.privateKey, suite.wallet2.privateKey)

	// Test that signatures are different for the same message
	testHash := crypto.Keccak256Hash([]byte("test message"))

	sig1, err := suite.wallet.SignTransaction(testHash)
	suite.NoError(err)

	sig2, err := suite.wallet2.SignTransaction(testHash)
	suite.NoError(err)

	suite.NotEqual(sig1, sig2)
}

func (suite *WalletTestSuite) TestMockWalletSignatureVerification() {
	testHash := crypto.Keccak256Hash([]byte("test message"))

	// Sign with first wallet
	sig1, err := suite.wallet.SignTransaction(testHash)
	suite.NoError(err)

	// Verify signature with correct public key
	pubkey1 := suite.wallet.privateKey.Public().(*ecdsa.PublicKey)
	signatureNoRecoverID := sig1[:len(sig1)-1]
	valid := crypto.VerifySignature(
		crypto.FromECDSAPub(pubkey1),
		testHash.Bytes(),
		signatureNoRecoverID,
	)
	suite.True(valid)

	// Verify signature with wrong public key (should fail)
	pubkey2 := suite.wallet2.privateKey.Public().(*ecdsa.PublicKey)
	valid = crypto.VerifySignature(
		crypto.FromECDSAPub(pubkey2),
		testHash.Bytes(),
		signatureNoRecoverID,
	)
	suite.False(valid)
}
