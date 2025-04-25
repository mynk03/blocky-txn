// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus_client

import (
	"blockchain-simulator/internal/blockchain"
	consensus "blockchain-simulator/internal/consensus"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// ConsensusClient is the main client for participating in consensus
type ConsensusClient struct {
	// ctx is the parent context for all operations within this client
	// Canceling this context will stop all goroutines started by this client
	ctx context.Context

	// cancel is the function to call when shutting down the client
	// Invoking this will cancel the ctx and terminate all operations
	cancel context.CancelFunc

	// host is the libp2p host that manages peer connections
	// Responsible for network communication with other nodes
	host host.Host

	// pubsub is the publish/subscribe system for message distribution
	// Uses GossipSub protocol for efficient message propagation
	pubsub *pubsub.PubSub

	// topic is the named pubsub channel where consensus messages are exchanged
	topic *pubsub.Topic

	// subscription is the client's subscription to the consensus topic
	// Used to receive incoming messages from other nodes
	subscription *pubsub.Subscription

	// Consensus is the consensus algorithm implementation
	// Handles validator selection, rewards, and slashing logic
	Consensus consensus.ConsensusAlgorithm

	// selfAddress is this node's Ethereum address for validation
	// Used to identify this node in the validator set
	selfAddress common.Address

	// discoveryService handles peer discovery using mDNS
	// Automatically finds other consensus nodes on the local network
	discoveryService mdns.Service

	// Channels for message handling
	// proposalCh receives block proposals from other validators
	proposalCh chan *blockchain.Block

	// voteCh receives votes on blocks from other validators
	voteCh chan *VoteData

	// evidenceCh receives evidence of validator misbehavior
	evidenceCh chan *EvidenceData

	// For keeping track of seen messages to prevent duplicates
	// seenMessages tracks message IDs that have already been processed
	// Prevents reprocessing duplicate messages from different peers
	seenMessages map[string]bool

	// seenMutex protects concurrent access to the seenMessages map
	// Ensures thread safety when checking or updating processed messages
	seenMutex sync.RWMutex

	// For tracking last seen validators
	// lastSeenValidators maps validator addresses to the last time they were seen active on the network
	// Used to detect offline validators who have stopped participating in consensus
	lastSeenValidators map[common.Address]time.Time

	// lastSeenMutex protects concurrent access to the lastSeenValidators map
	// Ensures thread safety when updating validator timestamps from different goroutines
	lastSeenMutex sync.RWMutex

	// validatorOfflineThreshold defines how long a validator can be unseen before being considered offline
	// When a validator hasn't been seen for this duration, they may be reported as missed validation
	validatorOfflineThreshold time.Duration

	// logger provides structured logging for the client
	// Records important events, errors, and debugging information
	logger *logrus.Logger

	// harborClient is the client for communicating with the execution client via the Harbor API
	// Responsible for requesting block creation and validation
	harborClient ExecutionClient

	// voteTracker keeps track of validator voting behavior
	voteTracker *VoteTracker

	// Genesis timestamp
	genesisTimestamp uint64
}

// NewConsensusClient creates a new consensus client with a validator address derived from
// an environment variable or randomly generated if the environment variable is not set
func NewConsensusClient(
	listenAddr string,
	initialStake uint64,
	logger *logrus.Logger,
) (*ConsensusClient, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize a logger if not provided
	if logger == nil {
		logger = logrus.New()
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
		logger.SetLevel(logrus.InfoLevel)
	}

	// Get validator address from private key in environment variable or generate randomly
	var selfAddress common.Address

	// Check if a validator private key is provided in environment variables
	privateKeyHex := os.Getenv("VALIDATOR_PRIVATE_KEY")
	if privateKeyHex != "" {
		// Remove "0x" prefix if present
		privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

		// Parse the private key
		privateKey, err := crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to parse validator private key: %w", err)
		}

		// Derive public key and address
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			cancel()
			return nil, fmt.Errorf("failed to get public key from private key")
		}

		selfAddress = crypto.PubkeyToAddress(*publicKeyECDSA)
		logger.WithField("address", selfAddress.Hex()).Info("Using validator address from environment variable")
	} else {
		// No private key provided, generate a random address
		randBytes := make([]byte, 20)
		if _, err := rand.Read(randBytes); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to generate random address: %w", err)
		}
		selfAddress = common.BytesToAddress(randBytes)
		logger.WithField("address", selfAddress.Hex()).Info("Generated random validator address (no private key found)")
	}

	// Create a new Proof of Stake consensus instance with default parameters
	slotDuration := 12 * time.Second
	minStake := uint64(100)
	baseReward := uint64(10)
	posConsensus := consensus.NewProofOfStake(slotDuration, minStake, baseReward)

	// Add our initial stake to become a validator
	if initialStake >= minStake {
		posConsensus.Deposit(selfAddress, initialStake)
		logger.WithFields(logrus.Fields{
			"address": selfAddress.Hex(),
			"stake":   initialStake,
		}).Info("Added initial stake for validator")
	} else if initialStake > 0 {
		logger.WithFields(logrus.Fields{
			"address":  selfAddress.Hex(),
			"stake":    initialStake,
			"minStake": minStake,
		}).Warn("Initial stake below minimum, not added as validator")
	}

	// Create a new libp2p host
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Create a new GossipSub instance
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		cancel()
		h.Close()
		return nil, fmt.Errorf("failed to create gossipsub: %w", err)
	}

	// Create the consensus client
	client := &ConsensusClient{
		ctx:                       ctx,
		cancel:                    cancel,
		host:                      h,
		pubsub:                    ps,
		Consensus:                 posConsensus,
		selfAddress:               selfAddress,
		proposalCh:                make(chan *blockchain.Block, 100),
		voteCh:                    make(chan *VoteData, 100),
		evidenceCh:                make(chan *EvidenceData, 100),
		seenMessages:              make(map[string]bool),
		logger:                    logger,
		lastSeenValidators:        make(map[common.Address]time.Time),
		validatorOfflineThreshold: 15 * time.Minute, // 3x the announcement period
		voteTracker:               NewVoteTracker(),
	}

	// Check for Harbor service address in environment variable first
	envHarborAddr := os.Getenv("HARBOR_SERVICE_ADDR")

	// Set up the Harbor client if an address is provided (from env or parameter)
	if envHarborAddr != "" {
		harborClient, err := NewHarborClient(envHarborAddr, logger)
		if err != nil {
			cancel()
			h.Close()
			return nil, fmt.Errorf("failed to create Harbor client: %w", err)
		}
		client.harborClient = harborClient

		// Log the source of the address
		if envHarborAddr != "" {
			logger.WithField("address", envHarborAddr).Info("Connected to execution client via Harbor service (from environment variable)")
		} else {
			logger.WithField("address", envHarborAddr).Info("Connected to execution client via Harbor service (from parameter)")
		}
	} else {
		logger.Warn("No Harbor service address provided, will operate without execution client integration")
	}

	logger.WithFields(logrus.Fields{
		"peerID":    h.ID().String(),
		"addrs":     h.Addrs(),
		"validator": selfAddress.Hex(),
	}).Info("Created new consensus client")

	client.genesisTimestamp = viper.GetUint64("GENESIS_TIMESTAMP")

	return client, nil
}

// Start initializes and starts the consensus client
func (c *ConsensusClient) Start() error {
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

	// Setup mDNS discovery
	c.discoveryService = mdns.NewMdnsService(c.host, ProtocolID, &discoveryNotifee{c: c})
	if err := c.discoveryService.Start(); err != nil {
		return fmt.Errorf("failed to start discovery service: %w", err)
	}

	// Start message handling goroutine
	go c.handleMessages()

	// Start validator selection loop in a goroutine
	go c.runValidatorSelectionLoop()

	// Start monitoring for offline validators
	go c.monitorOfflineValidators()

	// Start garbage collection for seen messages
	go c.GarbageCollectSeenMessages(5 * time.Minute)

	// Start periodic vote tracking cleanup
	go c.runVoteTrackerCleanup(10 * time.Minute)

	// Start periodic validator behavior monitoring
	go c.runValidatorBehaviorMonitoring(15 * time.Minute)

	// If we have stake, we're a validator - record our presence and start announcement loop
	if c.Consensus.GetValidatorStake(c.selfAddress) > 0 {
		// Record ourselves as seen
		c.recordValidatorSeen(c.selfAddress)

		// Start validator announcement loop
		go c.runValidatorAnnouncementLoop()
	}

	c.logger.Info("Consensus client started successfully")
	return nil
}

// Stop gracefully shuts down the consensus client
func (c *ConsensusClient) Stop() error {
	c.logger.Info("Stopping consensus client")

	if c.subscription != nil {
		c.subscription.Cancel()
	}

	if c.topic != nil {
		c.topic.Close()
	}

	// Close harbor client connection if it exists
	if c.harborClient != nil {
		if err := c.harborClient.Close(); err != nil {
			c.logger.WithError(err).Warn("Failed to close Harbor client connection")
		}
	}

	// mDNS discovery service will stop when the context is cancelled
	c.cancel()

	if c.host != nil {
		if err := c.host.Close(); err != nil {
			return fmt.Errorf("failed to close host: %w", err)
		}
	}

	close(c.proposalCh)
	close(c.voteCh)
	close(c.evidenceCh)

	return nil
}

// GetProposalChannel returns the channel for receiving block proposals
func (c *ConsensusClient) GetProposalChannel() <-chan *blockchain.Block {
	return c.proposalCh
}

// GetVoteChannel returns the channel for receiving votes
func (c *ConsensusClient) GetVoteChannel() <-chan *VoteData {
	return c.voteCh
}

// GetEvidenceChannel returns the channel for receiving evidence
func (c *ConsensusClient) GetEvidenceChannel() <-chan *EvidenceData {
	return c.evidenceCh
}

// GetValidatorAddress returns the validator address used by this client
func (c *ConsensusClient) GetValidatorAddress() common.Address {
	return c.selfAddress
}
