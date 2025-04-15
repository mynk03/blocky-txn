package execution_client

import (
	"github.com/gin-gonic/gin"
)

// Server represents the API server for the execution client
type Server struct {
	client *ExecutionClient
	router *gin.Engine
}

// NewServer creates a new API server instance
func NewServer(client *ExecutionClient) *Server {
	router := gin.Default()
	server := &Server{
		client: client,
		router: router,
	}

	// transaction endpoints
	router.POST("/transaction", server.addTransaction)
	router.GET("/txn/pool/transactions", server.getTransactions)
	router.GET("/transaction/:txn_hash", server.getTransactionByHash)
	
	// Testing endpoints
	router.GET("/node/id", server.getNodeId)
	router.GET("/test/peers", server.getAllPeers)
	router.POST("/test/peer/connect", server.connectToPeer)

	//user Account endpoints
	router.GET("/user/account/:address", server.getUserAccount)
	router.GET("/user/transactions/:sender_address", server.getUserTransactions)

	return server
}

// Start starts the API server
func (s *Server) Start(port string) error {
	return s.router.Run(":" + port)
}
