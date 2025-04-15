package execution_client

import (
	"blockchain-simulator/transaction"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to read request body: %v", err)})
		return
	}

	var req TransactionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request: %v", err)})
		return
	}

	// Validate sender's addresses
	sender := common.HexToAddress(req.Sender)
	if sender == (common.Address{}) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sender address"})
		return
	}

	// Validate receiver's addresses
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

	signature, err := hex.DecodeString(req.Signature)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot decode signature: " + err.Error()})
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
		Signature:       signature,
	}

	// validate transaction hash
	if tx.TransactionHash != tx.GenerateHash() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "transaction hash mismatch"})
		return
	}

	// Verify signature
	valid, err := tx.Verify()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "transaction signature verification failed: " + err.Error()})
		return
	}

	// if signature is not valid, return error
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "transaction signature verification failed"})
		return
	}

	// Validate transaction with current state of node
	if status, err := tx.ValidateWithState(s.client.chain.StateTrie); !status {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
	c.JSON(http.StatusOK, gin.H{"peerID": nodeId})
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
		strings.Contains(addr, "/p2p/")
}

// getUserAccount returns the user's account
func (s *Server) getUserAccount(c *gin.Context) {
	address := c.Param("address")
	account, err := s.client.chain.StateTrie.GetAccount(common.HexToAddress(address))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get account: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"account": account})
}


// getTransactionByHash returns the transaction by hash
func (s *Server) getTransactionByHash(c *gin.Context) {
	hash := c.Param("txn_hash")
	tx, err := s.client.chain.Storage.GetTransaction(hash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get transaction: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"transaction": tx})
}

// getUserTransactions returns all transactions by sender address
func (s *Server) getUserTransactions(c *gin.Context) {
	address := c.Param("sender_address")
	transactions, err := s.client.chain.Storage.GetTransactionsBySender(common.HexToAddress(address))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get transactions: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"transactions": transactions})
}
