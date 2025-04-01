package execution_client

import (
	"blockchain-simulator/transaction"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

const (
	// Protocol ID for transaction messages
	TransactionProtocolID = "/blockchain/transaction/1.0.0"
)

// Message represents a network message
type Message struct {
	Topic   string          `json:"topic"`
	Payload json.RawMessage `json:"payload"`
	Type    string          `json:"type"`
}

// ExecutionClient represents a client in the execution layer
type ExecutionClient struct {
	host    host.Host
	peers   map[peer.ID]struct{}
	mu      sync.RWMutex
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	txPool  *transaction.TransactionPool
}

// NewExecutionClient creates a new execution client instance
func NewExecutionClient(txPool *transaction.TransactionPool) (*ExecutionClient, error) {
	if txPool == nil {
		return nil, fmt.Errorf("transaction pool cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create a new libp2p host
	host, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.DisableRelay(),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %v", err)
	}

	client := &ExecutionClient{
		host:    host,
		peers:   make(map[peer.ID]struct{}),
		mu:      sync.RWMutex{},
		ctx:     ctx,
		cancel:  cancel,
		stopped: false,
		txPool:  txPool,
	}

	// Set up protocol handler for transactions
	host.SetStreamHandler(TransactionProtocolID, client.handleTransactionStream)

	// Set up connection manager notifications
	host.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			client.mu.Lock()
			client.peers[conn.RemotePeer()] = struct{}{}
			client.mu.Unlock()
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			client.mu.Lock()
			delete(client.peers, conn.RemotePeer())
			client.mu.Unlock()
		},
	})

	return client, nil
}

// Start starts the execution client
func (c *ExecutionClient) Start() error {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return fmt.Errorf("client is stopped")
	}
	c.mu.Unlock()
	return nil
}

// Stop stops the execution client
func (c *ExecutionClient) Stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	c.mu.Unlock()

	c.cancel()
	c.host.Close()
}

// GetAddress returns the multiaddress of the execution client
func (c *ExecutionClient) GetAddress() string {
	return c.host.Addrs()[0].String() + "/p2p/" + c.host.ID().String()
}

// ConnectToPeer connects to another execution client
func (c *ExecutionClient) ConnectToPeer(addr string) error {
	c.mu.RLock()
	if c.stopped {
		c.mu.RUnlock()
		return fmt.Errorf("client is stopped")
	}
	c.mu.RUnlock()

	targetAddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	targetInfo, err := peer.AddrInfoFromP2pAddr(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid peer address: %w", err)
	}

	c.host.Peerstore().AddAddrs(targetInfo.ID, targetInfo.Addrs, peerstore.PermanentAddrTTL)

	if err := c.host.Connect(c.ctx, *targetInfo); err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	time.Sleep(50 * time.Millisecond)

	if c.host.Network().Connectedness(targetInfo.ID) != network.Connected {
		return fmt.Errorf("connection not established with peer")
	}

	c.mu.Lock()
	c.peers[targetInfo.ID] = struct{}{}
	c.mu.Unlock()

	return nil
}

// GetPeers returns the list of connected peer addresses
func (c *ExecutionClient) GetPeers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	peers := make([]string, 0, len(c.peers))
	for peerID := range c.peers {
		if c.host.Network().Connectedness(peerID) == network.Connected {
			peerInfo := c.host.Peerstore().PeerInfo(peerID)
			if len(peerInfo.Addrs) > 0 {
				peers = append(peers, peerInfo.Addrs[0].String()+"/p2p/"+peerID.String())
			}
		}
	}
	return peers
}

// IsConnectedTo checks if the client is connected to a specific peer
func (c *ExecutionClient) IsConnectedTo(addr string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	targetAddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return false
	}

	targetInfo, err := peer.AddrInfoFromP2pAddr(targetAddr)
	if err != nil {
		return false
	}

	_, exists := c.peers[targetInfo.ID]
	return exists && c.host.Network().Connectedness(targetInfo.ID) == network.Connected
}

// broadcast sends a message to all connected peers
func (c *ExecutionClient) broadcast(protocolID string, msg Message) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.peers) == 0 {
		return fmt.Errorf("no connected peers")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	protocol := protocol.ID(protocolID)
	successfulBroadcasts := 0

	for peerID := range c.peers {
		if c.host.Network().Connectedness(peerID) != network.Connected {
			continue
		}

		stream, err := c.host.NewStream(c.ctx, peerID, protocol)
		if err != nil {
			log.Printf("Failed to create stream to peer %s: %v", peerID, err)
			continue
		}

		if _, err := stream.Write(append(data, '\n')); err != nil {
			log.Printf("Failed to write to stream: %v", err)
			stream.Reset()
			continue
		}

		stream.Close()
		successfulBroadcasts++
	}

	if successfulBroadcasts == 0 {
		return fmt.Errorf("failed to broadcast message to any peers")
	}

	return nil
}

// handleTransactionStream handles incoming transaction streams
func (c *ExecutionClient) handleTransactionStream(s network.Stream) {
	defer s.Close()

	var msg Message
	if err := json.NewDecoder(s).Decode(&msg); err != nil {
		log.Printf("Failed to decode message: %v", err)
		return
	}

	var tx transaction.Transaction
	if err := json.Unmarshal(msg.Payload, &tx); err != nil {
		log.Printf("Failed to unmarshal transaction: %v", err)
		return
	}

	if err := c.validateTransaction(tx); err != nil {
		log.Printf("Invalid transaction received: %v", err)
		return
	}

	if err := c.txPool.AddTransaction(tx); err != nil {
		log.Printf("Failed to add transaction to pool: %v", err)
		return
	}
}

// validateTransaction checks if a transaction is valid
func (c *ExecutionClient) validateTransaction(tx transaction.Transaction) error {
	if tx.Amount == 0 {
		return fmt.Errorf("transaction amount cannot be zero")
	}

	if tx.From == (common.Address{}) {
		return fmt.Errorf("transaction must have a valid sender address")
	}
	if tx.To == (common.Address{}) {
		return fmt.Errorf("transaction must have a valid recipient address")
	}

	if tx.Timestamp == 0 {
		return fmt.Errorf("transaction must have a valid timestamp")
	}

	return nil
}

// BroadcastTransaction broadcasts a transaction to all connected peers
func (c *ExecutionClient) BroadcastTransaction(tx transaction.Transaction) error {
	c.mu.RLock()
	if c.stopped {
		c.mu.RUnlock()
		return fmt.Errorf("client is stopped")
	}
	c.mu.RUnlock()

	if err := c.validateTransaction(tx); err != nil {
		return fmt.Errorf("invalid transaction: %w", err)
	}

	if err := c.txPool.AddTransaction(tx); err != nil {
		return fmt.Errorf("failed to add transaction to local pool: %w", err)
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	msg := Message{
		Topic:   "transaction",
		Payload: data,
		Type:    "transaction",
	}

	return c.broadcast(TransactionProtocolID, msg)
}
