package execution_client

import (
	"blockchain-simulator/transaction"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// TransactionRequest represents a transaction request with all fields
type TransactionRequest struct {
	Sender    string `json:"sender" binding:"required"`
	Receiver  string `json:"receiver" binding:"required"`
	Amount    uint64 `json:"amount" binding:"required"`
	Nonce     uint64 `json:"nonce" binding:"required"`
	Signature string `json:"signature" binding:"required"`
}

// ConnectPeerRequest represents a peer connection request
type ConnectPeerRequest struct {
	Address string `json:"address" binding:"required"`
}

// addTransaction handles transaction addition requests
func (s *Server) addTransaction(c *gin.Context) {
	var req TransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request: %v", err)})
		return
	}

	// Create transaction
	tx := transaction.Transaction{
		Sender:    transaction.AddressFromString(req.Sender),
		Receiver:  transaction.AddressFromString(req.Receiver),
		Amount:    req.Amount,
		Nonce:     req.Nonce,
		Timestamp: uint64(time.Now().Unix()),
		Status:    transaction.Pending,
		Signature: []byte(req.Signature),
	}

	// Generate transaction hash
	tx.TransactionHash = tx.GenerateHash()

	// Broadcast transaction
	if err := s.client.BroadcastTransaction(tx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to broadcast transaction: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"tx_hash": tx.TransactionHash,
	})
}

// getTransactions returns all transactions from the transaction pool
func (s *Server) getTransactions(c *gin.Context) {
	transactions := s.client.txPool.GetAllTransactions()
	c.JSON(http.StatusOK, gin.H{"transactions": transactions})
}

// getNodeId returns the node's ID
func (s *Server) getNodeId(c *gin.Context) {
	nodeId := s.client.GetPeerID()
	c.JSON(http.StatusOK, gin.H{"node_id": nodeId})
}

// getAllPeers returns all connected peers (testing endpoint)
func (s *Server) getAllPeers(c *gin.Context) {
	peers := s.client.GetPeers()
	c.JSON(http.StatusOK, gin.H{"peers": peers})
}

// connectToPeer handles peer connection requests (testing endpoint)
func (s *Server) connectToPeer(c *gin.Context) {
	var req ConnectPeerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request: %v", err)})
		return
	}

	// Connect to peer
	if err := s.client.ConnectToPeer(req.Address); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to connect to peer: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
