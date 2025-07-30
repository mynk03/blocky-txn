package execution

import (
	"blockchain-simulator/internal/blockchain"
	"blockchain-simulator/internal/transaction"
	"blockchain-simulator/internal/wallet"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type HandlersTestSuite struct {
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

func (suite *HandlersTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.testDataDir = "./testdata"
	err := os.MkdirAll(suite.testDataDir, 0755)
	suite.Require().NoError(err)

	suite.stakeAddress = common.HexToAddress("0x1234567890123456789012345678901234567890")
	suite.thresholdStake = uint64(400)

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

func (suite *HandlersTestSuite) TearDownTest() {
	if suite.chain != nil {
		suite.chain.Storage.Close()
	}
	os.RemoveAll(suite.testDataDir)
}

func TestHandlersTestSuite(t *testing.T) {
	suite.Run(t, new(HandlersTestSuite))
}

func (suite *HandlersTestSuite) TestGetPeersHandler() {
	// Create request
	req, err := http.NewRequest("GET", "/peers", nil)
	suite.Require().NoError(err)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Create gin context
	c, _ := gin.CreateTestContext(rr)
	c.Request = req

	// Call handler
	suite.server.getAllPeers(c)

	// Check status code
	suite.Equal(http.StatusOK, rr.Code)

	// Check response body
	var response map[string][]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Contains(response, "peers")
}

func (suite *HandlersTestSuite) TestGetTransactionPoolHandler() {
	// Create request
	req, err := http.NewRequest("GET", "/transactions", nil)
	suite.Require().NoError(err)

	// Create response recorder
	rr := httptest.NewRecorder()

	// Create gin context
	c, _ := gin.CreateTestContext(rr)
	c.Request = req

	// Call handler
	suite.server.getTransactions(c)

	// Check status code
	suite.Equal(http.StatusOK, rr.Code)

	// Check response body
	var response map[string][]transaction.Transaction
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	suite.Require().NoError(err)
	suite.Contains(response, "transactions")
}

// func (suite *HandlersTestSuite) TestAddTransactionHandler() {
// 	// Create transaction
// 	tx := transaction.Transaction{
// 		Sender:    suite.wallet.GetAddress(),
// 		Receiver:  common.HexToAddress("0x1000001000000000000000000000000000000001"),
// 		Amount:    100,
// 		Nonce:     0,
// 		Status:    transaction.Pending,
// 		Timestamp: uint64(time.Now().Unix()),
// 	}
// 	tx.TransactionHash = tx.GenerateHash()

// 	signature, err := suite.wallet.SignTransaction(common.HexToHash(tx.TransactionHash))
// 	suite.Require().NoError(err)
// 	tx.Signature = signature

// 	// Create request body
// 	reqBody := TransactionRequest{
// 		TransactionHash: tx.TransactionHash,
// 		Sender:          tx.Sender.Hex(),
// 		Receiver:        tx.Receiver.Hex(),
// 		Amount:          tx.Amount,
// 		Nonce:           tx.Nonce,
// 		Timestamp:       tx.Timestamp,
// 		Signature:       hex.EncodeToString(tx.Signature),
// 	}

// 	// Marshal request body
// 	reqJSON, err := json.Marshal(reqBody)
// 	suite.Require().NoError(err)

// 	// Create request
// 	req, err := http.NewRequest("POST", "/transaction", bytes.NewBuffer(reqJSON))
// 	suite.Require().NoError(err)
// 	req.Header.Set("Content-Type", "application/json")

// 	// Create response recorder
// 	rr := httptest.NewRecorder()

// 	// Create gin context
// 	c, _ := gin.CreateTestContext(rr)
// 	c.Request = req

// 	// Call handler
// 	suite.server.addTransaction(c)

// 	// Check status code
// 	suite.Equal(http.StatusOK, rr.Code)

// 	// Check response body
// 	var response map[string]string
// 	err = json.Unmarshal(rr.Body.Bytes(), &response)
// 	suite.Require().NoError(err)
// 	suite.Contains(response, "status")
// 	suite.Equal("success", response["status"])
// }

func (suite *HandlersTestSuite) TestAddTransactionHandlerInvalidJSON() {
	// Create invalid JSON
	invalidJSON := []byte("invalid json")

	// Create request
	req, err := http.NewRequest("POST", "/transactions", bytes.NewBuffer(invalidJSON))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	rr := httptest.NewRecorder()

	// Create gin context
	c, _ := gin.CreateTestContext(rr)
	c.Request = req

	// Call handler
	suite.server.addTransaction(c)

	// Check status code
	suite.Equal(http.StatusBadRequest, rr.Code)
}

func (suite *HandlersTestSuite) TestAddTransactionHandlerInvalidTransaction() {
	// Create invalid transaction (missing required fields)
	reqBody := TransactionRequest{
		Sender: suite.wallet.GetAddress().Hex(),
		// Missing Receiver
		Amount: 100,
		Nonce:  0,
	}

	// Marshal request body
	reqJSON, err := json.Marshal(reqBody)
	suite.Require().NoError(err)

	// Create request
	req, err := http.NewRequest("POST", "/transactions", bytes.NewBuffer(reqJSON))
	suite.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	rr := httptest.NewRecorder()

	// Create gin context
	c, _ := gin.CreateTestContext(rr)
	c.Request = req

	// Call handler
	suite.server.addTransaction(c)

	// Check status code
	suite.Equal(http.StatusBadRequest, rr.Code)
}
