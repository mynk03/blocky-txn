package rpc

import (
	"blockchain-simulator/execution_client"
	"blockchain-simulator/transaction"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Server represents the RPC server
type Server struct {
	client *execution_client.ExecutionClient
}

// NewServer creates a new RPC server instance
func NewServer(client *execution_client.ExecutionClient) *Server {
	return &Server{
		client: client,
	}
}

// TransactionRequest represents a transaction request
type TransactionRequest struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
}

// ConnectPeerRequest represents a peer connection request
type ConnectPeerRequest struct {
	Address string `json:"address"`
}

// SendTransaction handles transaction requests
func (s *Server) SendTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Create transaction
	tx := transaction.Transaction{
		From:      transaction.AddressFromString(req.From),
		To:        transaction.AddressFromString(req.To),
		Amount:    req.Amount,
		Timestamp: uint64(time.Now().Unix()),
	}

	// Broadcast transaction
	if err := s.client.BroadcastTransaction(tx); err != nil {
		http.Error(w, fmt.Sprintf("Failed to broadcast transaction: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// ConnectPeer handles peer connection requests
func (s *Server) ConnectPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ConnectPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Connect to peer
	if err := s.client.ConnectToPeer(req.Address); err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to peer: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// GetPeers returns the list of connected peers
func (s *Server) GetPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peers := s.client.GetPeers()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string][]string{"peers": peers})
}

// GetPeerID returns the node's own peer ID
func (s *Server) GetPeerID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	peerID := s.client.GetPeerID()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"peer_id": peerID})
}

// Start starts the RPC server
func (s *Server) Start(port string) error {
	http.HandleFunc("/transaction", s.SendTransaction)
	http.HandleFunc("/peer/connect", s.ConnectPeer)
	http.HandleFunc("/peer/list", s.GetPeers)
	http.HandleFunc("/peer/id", s.GetPeerID)

	return http.ListenAndServe(":"+port, nil)
}
