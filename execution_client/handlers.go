package execution_client

import (
	"blockchain-simulator/transaction"
	"fmt"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
)

// TransactionRequest represents a transaction request with all fields
type TransactionRequest struct {
	TransactionHash string `json:"transactionHash" binding:"required"`
	Sender          string `json:"sender" binding:"required"`
	Receiver        string `json:"receiver" binding:"required"`
	Amount          uint64 `json:"amount" binding:"required"`
	Nonce           uint64 `json:"nonce" binding:"required"`
	Timestamp       uint64 `json:"timestamp" binding:"required"`
	Signature       string `json:"signature" binding:"required"`
}

// ConnectPeerRequest represents a peer connection request
type ConnectPeerRequest struct {
	PeerID string `json:"peerID" binding:"required"`
}

// addTransaction handles transaction addition requests
func (s *Server) addTransaction(c *gin.Context) {
	var req TransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request: %v", err)})
		return
	}

	// Validate addresses
	sender := common.HexToAddress(req.Sender)
	if sender == (common.Address{}) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sender address"})
		return
	}

	receiver := common.HexToAddress(req.Receiver)
	if receiver == (common.Address{}) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid receiver address"})
		return
	}

	// Validate timestamp
	if req.Timestamp == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid timestamp"})
		return
	}

	// Create transaction
	tx := transaction.Transaction{
		TransactionHash: req.TransactionHash,
		Sender:          sender,
		Receiver:        receiver,
		Amount:          req.Amount,
		Nonce:           req.Nonce,
		Timestamp:       req.Timestamp,
		Status:          transaction.Pending,
	}

	// validate transaction hash
	if tx.TransactionHash == tx.GenerateHash() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "transaction hash mismatch"})
		return
	}

	// Validate transaction with current state of node
	if status, err := tx.ValidateWithState(s.client.chain.StateTrie); !status {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify signature
	if _, err := tx.Verify(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "transaction signature verification failed: " + err.Error()})
		return
	}

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
	nodeId := s.client.GetAddress()
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

	// Validate peer address format
	if !isValidPeerAddress(req.PeerID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid peer address format"})
		return
	}

	// Connect to peer
	if err := s.client.ConnectToPeer(req.PeerID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to connect to peer: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// isValidPeerAddress checks if the peer address is in the correct format
func isValidPeerAddress(addr string) bool {
	// Basic validation for multiaddr format
	// Should start with /ip4/ and contain /p2p/
	return len(addr) > 0 && addr[0] == '/' &&
		len(addr) >= 5 && addr[:5] == "/ip4/" &&
		len(addr) >= 5 && addr[len(addr)-5:] == "/p2p/"
}
