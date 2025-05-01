package execution

import (
	"blockchain-simulator/internal/blockchain"
	"blockchain-simulator/internal/transaction"
	"blockchain-simulator/internal/wallet"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	server         *Server
	client         *ExecutionClient
	txPool         *transaction.TransactionPool
	chain          *blockchain.Blockchain
	wallet         *wallet.MockWallet
	logger         *logrus.Logger
	testDataDir    string
	stakeAddress   common.Address
	thresholdStake uint64
}

func (suite *ServerTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.testDataDir = "./testdata"
	err := os.MkdirAll(suite.testDataDir, 0755)
	suite.Require().NoError(err)

	suite.thresholdStake = uint64(400)
	suite.stakeAddress = common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Create wallet
	suite.wallet, err = wallet.NewMockWallet()
	suite.Require().NoError(err)

	// Create transaction pool
	suite.txPool = transaction.NewTransactionPool()

	// Create blockchain storage
	storage, err := blockchain.NewLevelDBStorage(filepath.Join(suite.testDataDir, "node1"))
	suite.Require().NoError(err)

	// Create blockchain with initial account
	accounts := []string{suite.wallet.GetAddress().Hex()}
	amounts := []uint64{1000}
	stakeAmounts := []uint64{1000}
	suite.chain = blockchain.NewBlockchain(storage, accounts, amounts, stakeAmounts, suite.thresholdStake, suite.stakeAddress)

	// Create harbor server
	harborServer := NewHarborServer(suite.txPool, suite.chain, accounts[0], suite.logger)

	// Create execution client
	suite.client, err = NewExecutionClient(
		"/ip4/127.0.0.1/tcp/0",
		suite.txPool,
		suite.chain,
		suite.wallet.GetAddress(),
		harborServer,
		suite.logger,
	)
	suite.Require().NoError(err)

	// Create server
	suite.server = NewServer(suite.client)
}

func (suite *ServerTestSuite) TearDownTest() {
	if suite.chain != nil {
		suite.chain.Storage.Close()
	}
	os.RemoveAll(suite.testDataDir)
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) TestNewServer() {
	// Test valid creation
	suite.Require().NotNil(suite.server)
	suite.Require().Equal(suite.client, suite.server.client)

	// Test nil client
	server := NewServer(nil)
	suite.Require().NotNil(server)
}

func (suite *ServerTestSuite) TestStartInvalidPort() {
	// Test invalid port
	err := suite.server.Start("invalid-port")
	suite.Require().Error(err)
}
