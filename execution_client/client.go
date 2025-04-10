package execution_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/transaction"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/sirupsen/logrus"
)

const (
	// ProtocolID is the protocol identifier for our gossip network
	ProtocolID = "/blockchain-simulator/execution/1.0.0"

	// TopicName is the name of the pubsub topic for consensus messages
	TopicName = "execution"

	// DiscoveryInterval is how often to look for peers
	DiscoveryInterval = 20 * time.Second
)

// ExecutionClient manages the p2p network for consensus algorithms
type ExecutionClient struct {
	ctx              context.Context
	cancel           context.CancelFunc
	host             host.Host
	pubsub           *pubsub.PubSub
	topic            *pubsub.Topic
	subscription     *pubsub.Subscription
	selfAddress      common.Address
	discoveryService mdns.Service
	txPool           *transaction.TransactionPool
	chain            *blockchain.Blockchain
	harborServer     *HarborServer

	// Channels for message handling
	transactionCh chan *transaction.Transaction

	// For keeping track of seen messages to prevent duplicates
	seenMessages map[string]bool
	seenMutex    sync.RWMutex

	logger *logrus.Logger
}

// NewExecutionClient creates a new execution client with a randomly generated validator address
func NewExecutionClient(
	listenAddr string,
	txPool *transaction.TransactionPool,
	chain *blockchain.Blockchain,
	validatorAddr common.Address,
	harborServer *HarborServer,
	logger *logrus.Logger,
) (*ExecutionClient, error) {
	if txPool == nil {
		return nil, fmt.Errorf("transaction pool cannot be nil")
	}

	if chain == nil {
		return nil, fmt.Errorf("blockchain cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize a logger if not provided
	if logger == nil {
		logger = logrus.New()
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
		logger.SetLevel(logrus.InfoLevel)
	}

	// Create a new libp2p host
	host, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Create a new GossipSub instance
	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		cancel()
		host.Close()
		return nil, fmt.Errorf("failed to create gossipsub: %w", err)
	}

	client := &ExecutionClient{
		ctx:           ctx,
		cancel:        cancel,
		host:          host,
		pubsub:        ps,
		selfAddress:   validatorAddr,
		txPool:        txPool,
		chain:         chain,
		transactionCh: make(chan *transaction.Transaction, 100),
		seenMessages:  make(map[string]bool),
		logger:        logger,
	}

	// Initialize harborServer
	client.harborServer = harborServer

	logger.WithFields(logrus.Fields{
		"peerID":    host.ID().String(),
		"addrs":     host.Addrs(),
		"validator": validatorAddr.Hex(),
	}).Info("Created new execution client")

	return client, nil
}

// Start initializes and starts the execution client
func (c *ExecutionClient) Start(harborServerPort string, httpServer *Server, httpServerPort string) error {

	// Setup mDNS discovery
	c.discoveryService = mdns.NewMdnsService(c.host, ProtocolID, &discoveryNotifee{c: c})
	if err := c.discoveryService.Start(); err != nil {
		return fmt.Errorf("failed to start discovery service: %w", err)
	}

	// Join the pubsub topic
	var err error
	c.topic, err = c.pubsub.Join(TopicName)
	if err != nil {
		return fmt.Errorf("failed to join topic: %w", err)
	}

	// Subscribe to the topic
	c.subscription, err = c.topic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to topic: %w", err)
	}

	// Start message handling goroutine
	go c.handleTransactions()

	// Start HTTP server for user interactions
	go func() {
		if err := httpServer.Start(httpServerPort); err != nil {
			c.logger.WithError(err).Error("Failed to start HTTP server")
		}
	}()

	// Start Harbor RPC server for consensus client
	go func() {
		if err := c.harborServer.StartServer(harborServerPort); err != nil {
			c.logger.WithError(err).Error("Failed to start Harbor RPC server")
		}
	}()

	c.logger.Info("Execution client started successfully")
	return nil
}

// Stop gracefully shuts down the execution client
func (c *ExecutionClient) Stop() error {
	c.logger.Info("Stopping execution client")

	if c.subscription != nil {
		c.subscription.Cancel()
	}

	if c.topic != nil {
		c.topic.Close()
	}

	// mDNS discovery service will stop when the context is cancelled
	c.cancel()

	if c.host != nil {
		if err := c.host.Close(); err != nil {
			return fmt.Errorf("failed to close host: %w", err)
		}
	}

	close(c.transactionCh)

	return nil
}

// handleTransactions processes incoming transactions from the subscription
func (c *ExecutionClient) handleTransactions() {
	for {
		msg, err := c.subscription.Next(c.ctx)
		if err != nil {
			if c.ctx.Err() != nil {
				// Context was canceled, client is shutting down
				return
			}
			c.logger.WithError(err).Error("Error receiving message from subscription")
			continue
		}

		// Skip messages from ourselves
		if msg.ReceivedFrom == c.host.ID() {
			continue
		}

		// Deserialize the transaction
		var tx transaction.Transaction
		if err := json.Unmarshal(msg.Data, &tx); err != nil {
			c.logger.WithError(err).Error("Failed to unmarshal transaction")
			continue
		}

		// // Verify the transaction signature
		// valid, err := tx.Verify()
		// if err != nil {
		// 	c.logger.WithError(err).WithFields(logrus.Fields{
		// 		"hash":   tx.TransactionHash,
		// 		"sender": tx.Sender.Hex(),
		// 	}).Error("Transaction verification failed")
		// 	continue
		// }

		// if !valid {
		// 	c.logger.WithFields(logrus.Fields{
		// 		"hash":   tx.TransactionHash,
		// 		"sender": tx.Sender.Hex(),
		// 	}).Error("Invalid transaction signature")
		// 	continue
		// }

		// Check if we've seen this transaction before
		c.seenMutex.RLock()
		seen := c.seenMessages[tx.TransactionHash]
		c.seenMutex.RUnlock()

		if seen {
			continue
		}

		// Mark transaction as seen
		c.seenMutex.Lock()
		c.seenMessages[tx.TransactionHash] = true
		c.seenMutex.Unlock()

		// Add transaction to pool
		if err := c.txPool.AddTransaction(tx); err != nil {
			c.logger.WithError(err).WithFields(logrus.Fields{
				"hash":   tx.TransactionHash,
				"sender": tx.Sender.Hex(),
			}).Error("Failed to add transaction to pool")
			continue
		}

		// Forward transaction to application
		select {
		case c.transactionCh <- &tx:
		default:
			c.logger.WithFields(logrus.Fields{
				"hash":   tx.TransactionHash,
				"sender": tx.Sender.Hex(),
			}).Warn("Transaction channel full, dropping message")
		}
	}
}

// discoveryNotifee is a struct for handling peer discovery notifications
type discoveryNotifee struct {
	c *ExecutionClient
}

// HandlePeerFound is called when a new peer is discovered
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	n.c.logger.WithFields(logrus.Fields{
		"peerID": pi.ID.String(),
		"addrs":  pi.Addrs,
	}).Info("Discovered new peer")

	// if err := n.c.host.Connect(n.c.ctx, pi); err != nil {
	// 	n.c.logger.WithError(err).WithField("peer", pi.ID).Warn("Failed to connect to discovered peer")
	// } else {
	// 	n.c.logger.WithFields(logrus.Fields{
	// 		"peerID": pi.ID.String(),
	// 		"addrs":  pi.Addrs,
	// 	}).Info("Connected to peer")
	// }
}

// GetAddress returns the multiaddress of the execution client
func (c *ExecutionClient) GetAddress() string {
	return c.host.Addrs()[0].String() + "/p2p/" + c.host.ID().String()
}

// GetPeers returns the list of connected peer addresses
func (c *ExecutionClient) GetPeers() []string {
	peers := c.host.Network().Peers()

	fmt.Println("peers: ", peers)

	peerAddrs := make([]string, 0, len(peers))

	for _, peerID := range peers {
		if c.host.Network().Connectedness(peerID) == network.Connected {
			peerInfo := c.host.Peerstore().PeerInfo(peerID)
			if len(peerInfo.Addrs) > 0 {
				peerAddrs = append(peerAddrs, peerInfo.Addrs[0].String()+"/p2p/"+peerID.String())
			}
		}
	}

	return peerAddrs
}

// ConnectToPeer establishes a connection to a peer
func (c *ExecutionClient) ConnectToPeer(peerAddr string) error {
	peerInfo, err := peer.AddrInfoFromString(peerAddr)
	if err != nil {
		return fmt.Errorf("invalid peer address: %w", err)
	}

	if err := c.host.Connect(c.ctx, *peerInfo); err != nil {
		return fmt.Errorf("failed to connect to peer: %w", err)
	}

	c.logger.WithField("peer", peerAddr).Info("Connected to peer")
	return nil
}

// BroadcastTransaction broadcasts a transaction to the network
func (c *ExecutionClient) BroadcastTransaction(tx transaction.Transaction) error {
	// Add transaction to local pool first
	if err := c.txPool.AddTransaction(tx); err != nil {
		return fmt.Errorf("failed to add transaction to pool: %w", err)
	}

	// Publish transaction to network
	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	if err := c.topic.Publish(c.ctx, data); err != nil {
		return fmt.Errorf("failed to publish transaction: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"hash":     tx.TransactionHash,
		"sender":   tx.Sender.Hex(),
		"receiver": tx.Receiver.Hex(),
		"amount":   tx.Amount,
	}).Info("Broadcasted transaction")

	return nil
}

// IsConnectedTo checks if the client is connected to a specific peer
func (c *ExecutionClient) IsConnectedTo(addr string) bool {
	peerInfo, err := peer.AddrInfoFromString(addr)
	if err != nil {
		return false
	}

	return c.host.Network().Connectedness(peerInfo.ID) == network.Connected
}
