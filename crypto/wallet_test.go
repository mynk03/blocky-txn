package crypto

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/suite"
	"github.com/tyler-smith/go-bip39"
)

type WalletTestSuite struct {
	suite.Suite
	mnemonic string
	wallet   *Wallet
}

func (suite *WalletTestSuite) SetupTest() {
	// Generate a new mnemonic for testing
	mnemonic, err := GenerateMnemonic()
	suite.NoError(err)
	suite.mnemonic = mnemonic

	// Create a new wallet
	wallet, err := GetWallet(mnemonic)
	suite.NoError(err)
	suite.wallet = wallet
}

func TestWalletTestSuite(t *testing.T) {
	suite.Run(t, new(WalletTestSuite))
}

func (suite *WalletTestSuite) TestGenerateMnemonic() {
	// Test generating a new mnemonic
	mnemonic, err := GenerateMnemonic()
	suite.NoError(err)
	suite.NotEmpty(mnemonic)
	suite.True(bip39.IsMnemonicValid(mnemonic))
}

func (suite *WalletTestSuite) TestPrivateKeyFromMnemonic() {
	// Test generating private key from mnemonic
	privateKey, err := PrivateKeyFromMnemonic(suite.mnemonic)
	suite.NoError(err)
	suite.NotNil(privateKey)

	// Test invalid mnemonic
	_, err = PrivateKeyFromMnemonic("invalid mnemonic")
	suite.Error(err)
}

func (suite *WalletTestSuite) TestAddressFromPrivateKey() {
	// Test generating address from private key
	address := AddressFromPrivateKey(suite.wallet.PrivateKey)
	suite.NotEmpty(address)
	suite.Equal(suite.wallet.Address, address)
}

func (suite *WalletTestSuite) TestGetWallet() {
	// Test creating a new wallet
	mnemonic2, err := GenerateMnemonic()
	suite.NoError(err)
	wallet, err := GetWallet(mnemonic2)
	suite.NoError(err)
	suite.NotNil(wallet)
	suite.NotNil(wallet.PrivateKey)
	suite.NotNil(wallet.PublicKey)
	suite.NotEmpty(wallet.Address)

	// Test creating wallet with invalid mnemonic
	_, err = GetWallet("invalid mnemonic")
	suite.Error(err)
}

func (suite *WalletTestSuite) TestSignAndVerifyTransaction() {
	// Create a test hash
	testTxHash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	// Sign the hash
	signature, err := suite.wallet.SignTransaction(testTxHash)
	suite.NoError(err)
	suite.NotNil(signature)

	// Verify the signature
	isValid := suite.wallet.VerifySignature(testTxHash, signature)
	suite.True(isValid)

	// Test verification with wrong hash
	wrongHash := common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	isValid = suite.wallet.VerifySignature(wrongHash, signature)
	suite.False(isValid)
}

func (suite *WalletTestSuite) TestDeterministicKeyGeneration() {
	// Create two wallets with the same mnemonic and index
	wallet1, err := GetWallet(suite.mnemonic)
	suite.NoError(err)

	wallet2, err := GetWallet(suite.mnemonic)
	suite.NoError(err)

	// Verify they have the same private key and address
	suite.Equal(wallet1.Address, wallet2.Address)
	suite.Equal(crypto.FromECDSA(wallet1.PrivateKey), crypto.FromECDSA(wallet2.PrivateKey))

	// Create a wallet with different index
	mnemonic3, err := GenerateMnemonic()
	suite.NoError(err)

	// Create a wallet with different index
	wallet3, err := GetWallet(mnemonic3)
	suite.NoError(err)

	// Verify it has different private key and address
	suite.NotEqual(wallet1.Address, wallet3.Address)
	suite.NotEqual(crypto.FromECDSA(wallet1.PrivateKey), crypto.FromECDSA(wallet3.PrivateKey))
}
