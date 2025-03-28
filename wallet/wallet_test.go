package wallet

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/tyler-smith/go-bip39"
)

type WalletTestSuite struct {
	suite.Suite
	mnemonic string
	wallet   Wallet
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
	// Since we're using an interface, we need to cast to access internal fields
	walletStruct, ok := suite.wallet.(*WalletStruct)
	suite.True(ok)

	address := AddressFromPrivateKey(walletStruct.PrivateKey)
	suite.NotEmpty(address)
	suite.Equal(walletStruct.Address, address)
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

func TestMockWalletCreation(t *testing.T) {
	// Create a new mock wallet
	wallet, err := NewMockWallet()
	assert.NoError(t, err)
	assert.NotNil(t, wallet)
	assert.NotEmpty(t, wallet.GetAddress())
}

func TestMockWalletWithAddress(t *testing.T) {
	// Create a mock wallet with a specific address
	addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	wallet, err := NewMockWalletWithAddress(addr)
	assert.NoError(t, err)
	assert.NotNil(t, wallet)
	assert.Equal(t, addr, wallet.GetAddress())
}

func TestMockWalletSignAndVerify(t *testing.T) {
	// Create a mock wallet
	wallet, err := NewMockWallet()
	assert.NoError(t, err)

	// Create a test hash to sign
	hash := common.HexToHash("0x1234567890123456789012345678901234567890123456789012345678901234")

	// Sign the hash
	signature, err := wallet.SignTransaction(hash)
	assert.NoError(t, err)
	assert.NotNil(t, signature)

	// Verify the signature
	isValid := wallet.VerifySignature(hash, signature)
	assert.True(t, isValid)

	// Test with wrong hash
	wrongHash := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000")
	isValid = wallet.VerifySignature(wrongHash, signature)
	assert.False(t, isValid)
}

func TestMultipleMockWallets(t *testing.T) {
	// Create multiple mock wallets
	wallet1, err := NewMockWallet()
	assert.NoError(t, err)

	wallet2, err := NewMockWallet()
	assert.NoError(t, err)

	// Ensure they have different addresses
	assert.NotEqual(t, wallet1.GetAddress(), wallet2.GetAddress())

	// Test cross-wallet signature verification
	hash := common.HexToHash("0x1234567890123456789012345678901234567890123456789012345678901234")

	// Sign with wallet1
	signature1, err := wallet1.SignTransaction(hash)
	assert.NoError(t, err)

	// Verify with both wallets
	assert.True(t, wallet1.VerifySignature(hash, signature1))
	assert.False(t, wallet2.VerifySignature(hash, signature1))

	// Sign with wallet2
	signature2, err := wallet2.SignTransaction(hash)
	assert.NoError(t, err)

	// Verify with both wallets
	assert.False(t, wallet1.VerifySignature(hash, signature2))
	assert.True(t, wallet2.VerifySignature(hash, signature2))
}

func TestMockWalletSignatureUniqueness(t *testing.T) {
	wallet1, err := NewMockWallet()
	assert.NoError(t, err)
	wallet2, err := NewMockWallet()
	assert.NoError(t, err)

	hash := common.HexToHash("0x1234567890123456789012345678901234567890123456789012345678901234")

	// Sign the same hash multiple times
	signature1, err := wallet1.SignTransaction(hash)
	assert.NoError(t, err)

	signature2, err := wallet2.SignTransaction(hash)
	assert.NoError(t, err)

	// Signatures should be valid
	assert.True(t, wallet1.VerifySignature(hash, signature1))
	assert.True(t, wallet2.VerifySignature(hash, signature2))

	// But they should be different (due to randomness in signing)
	assert.NotEqual(t, signature1, signature2)
}
