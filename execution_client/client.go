package execution_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/transaction"
	"blockchain-simulator/validator"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const (
	// Topic for transaction gossiping
	TransactionTopic = "blockchain-transactions"
)

// ExecutionClient represents a client in the execution layer
type ExecutionClient struct {
	host      host.Host
	peers     map[peer.ID]struct{}
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	stopped   bool
	txPool    *transaction.TransactionPool
	ps        *pubsub.PubSub
	txTopic   *pubsub.Topic
	txSub     *pubsub.Subscription
	validator *validator.Validator
	chain     *blockchain.Blockchain
}

// NewExecutionClient creates a new execution client instance
func NewExecutionClient(txPool *transaction.TransactionPool, chain *blockchain.Blockchain, validatorAddr common.Address) (*ExecutionClient, error) {
	if txPool == nil {
		return nil, fmt.Errorf("transaction pool cannot be nil")
	}

	if chain == nil {
		return nil, fmt.Errorf("blockchain cannot be nil")
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

	// Create a new PubSub service
	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		cancel()
		host.Close()
		return nil, fmt.Errorf("failed to create pubsub: %v", err)
	}

	// Create transaction topic
	txTopic, err := ps.Join(TransactionTopic)
	if err != nil {
		cancel()
		host.Close()
		return nil, fmt.Errorf("failed to join transaction topic: %v", err)
	}

	// Subscribe to transaction topic
	txSub, err := txTopic.Subscribe()
	if err != nil {
		cancel()
		host.Close()
		return nil, fmt.Errorf("failed to subscribe to transaction topic: %v", err)
	}

	// Create validator
	validator := validator.NewValidator(validatorAddr, txPool, chain)

	client := &ExecutionClient{
		host:      host,
		peers:     make(map[peer.ID]struct{}),
		mu:        sync.RWMutex{},
		ctx:       ctx,
		cancel:    cancel,
		stopped:   false,
		txPool:    txPool,
		ps:        ps,
		txTopic:   txTopic,
		txSub:     txSub,
		validator: validator,
		chain:     chain,
	}

	// Start the message handler
	go client.handleTransactionMessages()

	return client, nil
}

// handleTransactionMessages handles incoming transaction messages from the pubsub topic
func (c *ExecutionClient) handleTransactionMessages() {
	for {
		msg, err := c.txSub.Next(c.ctx)
		if err != nil {
			if err == context.Canceled {
				return
			}
			log.Printf("Error reading transaction message: %v", err)
			continue
		}

		// Only process messages from other peers
		if msg.ReceivedFrom == c.host.ID() {
			continue
		}

		var tx transaction.Transaction
		if err := json.Unmarshal(msg.Data, &tx); err != nil {
			log.Printf("Failed to unmarshal transaction: %v", err)
			continue
		}

		// Add transaction to validator
		if err := c.validator.AddTransaction(tx); err != nil {
			log.Printf("Failed to add transaction to validator: %v", err)
			continue
		}
	}
}

// CreateBlock creates a new block using the validator
func (c *ExecutionClient) CreateBlock() blockchain.Block {
	return c.validator.CreateNewBlock()
}

// BroadcastTransaction broadcasts a transaction to all connected peers
func (c *ExecutionClient) BroadcastTransaction(tx transaction.Transaction) error {
	c.mu.RLock()
	if c.stopped {
		c.mu.RUnlock()
		return fmt.Errorf("client is stopped")
	}
	c.mu.RUnlock()

	// Add transaction to validator first
	if err := c.validator.AddTransaction(tx); err != nil {
		return fmt.Errorf("invalid transaction: %w", err)
	}

	// Marshal transaction
	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	// Publish transaction to the topic
	if err := c.txTopic.Publish(c.ctx, data); err != nil {
		return fmt.Errorf("failed to publish transaction: %w", err)
	}

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
	c.txSub.Cancel()
	c.txTopic.Close()
	c.host.Close()
}

// GetAddress returns the multiaddress of the execution client
func (c *ExecutionClient) GetAddress() string {
	return c.host.Addrs()[0].String() + "/p2p/" + c.host.ID().String()
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
