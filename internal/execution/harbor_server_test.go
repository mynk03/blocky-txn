package execution

import (
	"blockchain-simulator/internal/blockchain"
	"blockchain-simulator/internal/transaction"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type HarborServerTestSuite struct {
	suite.Suite
	server         *HarborServer
	txPool         *transaction.TransactionPool
	chain          *blockchain.Blockchain
	logger         *logrus.Logger
	testDataDir    string
	stakeAddress   common.Address
	thresholdStake uint64
}

func (suite *HarborServerTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.testDataDir = "./testdata"
	err := os.MkdirAll(suite.testDataDir, 0755)
	suite.Require().NoError(err)

	suite.thresholdStake = uint64(400)
	suite.stakeAddress = common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create transaction pool
	suite.txPool = transaction.NewTransactionPool()

	// Create blockchain storage
	storage, err := blockchain.NewLevelDBStorage(filepath.Join(suite.testDataDir, "node1"))
	suite.Require().NoError(err)

	// Create blockchain with initial account
	accounts := []string{"0x100000100000000000000000000000000000000a"}
	amounts := []uint64{1000}
	stakeAmounts := []uint64{1000}
	suite.chain = blockchain.NewBlockchain(storage, accounts, amounts, stakeAmounts, suite.thresholdStake, suite.stakeAddress)

	// Create harbor server
	suite.server = NewHarborServer(suite.txPool, suite.chain, accounts[0], suite.logger)
}

func (suite *HarborServerTestSuite) TearDownTest() {
	if suite.chain != nil {
		suite.chain.Storage.Close()
	}
	os.RemoveAll(suite.testDataDir)
}

func TestHarborServerTestSuite(t *testing.T) {
	suite.Run(t, new(HarborServerTestSuite))
}

func (suite *HarborServerTestSuite) TestNewHarborServer() {
	// Test valid creation
	suite.Require().NotNil(suite.server)
	suite.Require().NotNil(suite.server.txPool)
	suite.Require().NotNil(suite.server.chain)
	suite.Require().NotNil(suite.server.logger)
	suite.Require().NotEmpty(suite.server.validatorAddr)

	// Test nil transaction pool
	server := NewHarborServer(nil, suite.chain, "0x100000100000000000000000000000000000000a", suite.logger)
	suite.Require().NotNil(server)

	// Test nil blockchain
	server = NewHarborServer(suite.txPool, nil, "0x100000100000000000000000000000000000000a", suite.logger)
	suite.Require().NotNil(server)

	// Test nil logger
	server = NewHarborServer(suite.txPool, suite.chain, "0x100000100000000000000000000000000000000a", nil)
	suite.Require().NotNil(server)
}

func (suite *HarborServerTestSuite) TestInvalidStartServer() {
	// Test invalid port
	err := suite.server.StartServer("invalid-port")
	suite.Require().Error(err)
}

func (suite *HarborServerTestSuite) TestGetTransactionPool() {
	// Test get transaction pool
	txPool := suite.server.txPool
	suite.Require().Equal(suite.txPool, txPool)
}

func (suite *HarborServerTestSuite) TestGetBlockchain() {
	// Test get blockchain
	chain := suite.server.chain
	suite.Require().Equal(suite.chain, chain)
}

func (suite *HarborServerTestSuite) TestGetValidatorAddress() {
	// Test get validator address
	addr := suite.server.validatorAddr
	suite.Require().NotEmpty(addr)
	suite.Require().Equal("0x100000100000000000000000000000000000000a", addr)
}
