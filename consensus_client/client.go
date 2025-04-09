// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/consensus"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
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
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/sirupsen/logrus"
)

const (
	// ProtocolID is the protocol identifier for our gossip network
	ProtocolID = "/blockchain-simulator/consensus/1.0.0"

	// TopicName is the name of the pubsub topic for consensus messages
	TopicName = "consensus"

	// DiscoveryInterval is how often to look for peers
	DiscoveryInterval = 1 * time.Minute
)

// MessageType denotes the type of consensus message
type MessageType int

const (
	// BlockProposal is a message containing a new block proposal
	BlockProposal MessageType = iota

	// Vote is a vote for a proposed block
	Vote

	// ValidationMissed is a notification that a validator missed their slot
	ValidationMissed

	// DoubleSignEvidence is evidence of a validator double signing
	DoubleSignEvidence

	// InvalidBlockEvidence is evidence of a validator proposing an invalid block
	InvalidBlockEvidence

	// ValidatorAnnouncement is a message announcing validator status
	ValidatorAnnouncement
)

// ExecutionClient represents the interface for interacting with the execution client (Harbor service)
type ExecutionClient interface {
	RequestBlockCreation(ctx context.Context, validatorAddress common.Address, prevBlockHash string, maxTransactions uint32) (*blockchain.Block, error)
	ValidateBlock(ctx context.Context, block *blockchain.Block) (bool, error)
	Close() error
}

// ConsensusMessage represents a message exchanged between consensus nodes
type ConsensusMessage struct {
	// Type indicates the category of this message (BlockProposal, Vote, ValidationMissed, etc.)
	Type MessageType `json:"type"`

	// Sender is the Ethereum address of the node that originated this message
	Sender common.Address `json:"sender"`

	// BlockData contains the full block information for block proposals
	// Only populated for messages of Type BlockProposal
	BlockData *blockchain.Block `json:"block_data,omitempty"`

	// Vote contains information about a validator's vote on a specific block
	// Only populated for messages of Type Vote
	Vote *VoteData `json:"vote,omitempty"`

	// Evidence contains proof of validator misbehavior (missed validations, double signs, etc.)
	// Only populated for messages of Type ValidationMissed, DoubleSignEvidence, or InvalidBlockEvidence
	Evidence *EvidenceData `json:"evidence,omitempty"`

	// ValidatorAddress is the Ethereum address of the validator being referenced
	// Primarily used in ValidatorAnnouncement messages
	ValidatorAddress common.Address `json:"validator_address,omitempty"`

	// ValidatorStake represents the amount of tokens staked by the validator
	// Used in ValidatorAnnouncement messages to communicate stake updates
	ValidatorStake uint64 `json:"validator_stake,omitempty"`

	// ValidatorMetrics contains performance statistics and status information about a validator
	// Used in ValidatorAnnouncement messages to share validator health data
	ValidatorMetrics *consensus.ValidationMetrics `json:"validator_metrics,omitempty"`

	// Timestamp records when this message was created
	// Used for message ordering and deduplication
	Timestamp time.Time `json:"timestamp"`
}

// VoteData contains information for a vote message
type VoteData struct {
	// BlockHash is the hash of the block being voted on
	BlockHash string `json:"block_hash"`

	// Validator is the Ethereum address of the validator casting this vote
	Validator common.Address `json:"validator"`

	// Approve indicates whether the validator approves (true) or rejects (false) the block
	Approve bool `json:"approve"`
}

// EvidenceData contains evidence of validator misbehavior
type EvidenceData struct {
	// Validator is the Ethereum address of the validator that misbehaved
	Validator common.Address `json:"validator"`

	// EvidenceType indicates the type of misbehavior (ValidationMissed, DoubleSignEvidence, etc.)
	EvidenceType MessageType `json:"evidence_type"`

	// BlockHash is the hash of the block involved in the misbehavior (if applicable)
	BlockHash string `json:"block_hash,omitempty"`

	// Reason provides a human-readable explanation of the misbehavior
	Reason string `json:"reason,omitempty"`
}

// VoteTracker tracks validator voting behavior to identify misbehaving validators
type VoteTracker struct {
	// votes maps block hashes to validator votes
	// blockHash -> validator address -> approve (true/false)
	votes map[string]map[common.Address]bool

	// localValidations stores the local node's validation result for each block
	// blockHash -> validation result (true=valid, false=invalid)
	localValidations map[string]bool

	// mutex protects concurrent access to the vote tracker
	mutex sync.RWMutex
}

// NewVoteTracker creates a new vote tracker
func NewVoteTracker() *VoteTracker {
	return &VoteTracker{
		votes:            make(map[string]map[common.Address]bool),
		localValidations: make(map[string]bool),
	}
}

// TrackVote records a validator's vote for a block
func (vt *VoteTracker) TrackVote(blockHash string, validator common.Address, approve bool) {
	vt.mutex.Lock()
	defer vt.mutex.Unlock()

	// Initialize map for this block if it doesn't exist
	if _, exists := vt.votes[blockHash]; !exists {
		vt.votes[blockHash] = make(map[common.Address]bool)
	}

	// Record the vote
	vt.votes[blockHash][validator] = approve
}

// RecordLocalValidation records the local node's validation result for a block
func (vt *VoteTracker) RecordLocalValidation(blockHash string, isValid bool) {
	vt.mutex.Lock()
	defer vt.mutex.Unlock()

	vt.localValidations[blockHash] = isValid
}

// IdentifyMisbehavingValidators returns a map of validators who voted contrary to
// the local node's validation for a given block
func (vt *VoteTracker) IdentifyMisbehavingValidators(blockHash string) map[common.Address]bool {
	vt.mutex.RLock()
	defer vt.mutex.RUnlock()

	misbehaving := make(map[common.Address]bool)

	// Get local validation result
	localResult, exists := vt.localValidations[blockHash]
	if !exists {
		// We haven't validated this block locally
		return misbehaving
	}

	// Check all votes for this block
	if votes, exists := vt.votes[blockHash]; exists {
		for validator, vote := range votes {
			// If validator voted differently than our local validation
			if vote != localResult {
				misbehaving[validator] = vote
			}
		}
	}

	return misbehaving
}

// GetVotes returns all votes for a given block
func (vt *VoteTracker) GetVotes(blockHash string) map[common.Address]bool {
	vt.mutex.RLock()
	defer vt.mutex.RUnlock()

	if votes, exists := vt.votes[blockHash]; exists {
		// Create a copy to avoid concurrent modification
		result := make(map[common.Address]bool, len(votes))
		for validator, vote := range votes {
			result[validator] = vote
		}
		return result
	}

	return make(map[common.Address]bool)
}

// GetLocalValidation returns the local validation result for a block
func (vt *VoteTracker) GetLocalValidation(blockHash string) (bool, bool) {
	vt.mutex.RLock()
	defer vt.mutex.RUnlock()

	result, exists := vt.localValidations[blockHash]
	return result, exists
}

// CleanupOldVotes removes vote tracking for old blocks
func (vt *VoteTracker) CleanupOldVotes(blockHash string) {
	vt.mutex.Lock()
	defer vt.mutex.Unlock()

	delete(vt.votes, blockHash)
	delete(vt.localValidations, blockHash)
}

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
	slotDuration := 5 * time.Second
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

// ProposeBlock broadcasts a new block proposal
func (c *ConsensusClient) ProposeBlock(block *blockchain.Block) error {
	msg := ConsensusMessage{
		Type:      BlockProposal,
		Sender:    c.selfAddress,
		BlockData: block,
		Timestamp: time.Now(),
	}

	return c.publishMessage(msg)
}

// SubmitVote broadcasts a vote for a block
func (c *ConsensusClient) SubmitVote(blockHash string, approve bool) error {
	vote := VoteData{
		BlockHash: blockHash,
		Validator: c.selfAddress,
		Approve:   approve,
	}

	msg := ConsensusMessage{
		Type:      Vote,
		Sender:    c.selfAddress,
		Vote:      &vote,
		Timestamp: time.Now(),
	}

	// Track our own vote
	c.voteTracker.TrackVote(blockHash, c.selfAddress, approve)

	// Record our local validation result if not already recorded
	_, exists := c.voteTracker.GetLocalValidation(blockHash)
	if !exists {
		c.voteTracker.RecordLocalValidation(blockHash, approve)
	}

	return c.publishMessage(msg)
}

// ReportMissedValidation reports that a validator missed their validation slot
func (c *ConsensusClient) ReportMissedValidation(validator common.Address) error {
	evidence := EvidenceData{
		Validator:    validator,
		EvidenceType: ValidationMissed,
		Reason:       "Validator missed their validation slot",
	}

	msg := ConsensusMessage{
		Type:      ValidationMissed,
		Sender:    c.selfAddress,
		Evidence:  &evidence,
		Timestamp: time.Now(),
	}

	// Record the missed validation in the consensus mechanism
	c.Consensus.RecordMissedValidation(validator)

	c.logger.WithFields(logrus.Fields{
		"validator": validator.Hex(),
	}).Info("Missed block production recorded")

	// Attempt to publish, but don't fail if this doesn't work
	// (e.g., during tests or when the network is down)
	if err := c.publishMessage(msg); err != nil {
		c.logger.WithError(err).Debug("Failed to publish missed validation report")
		return err
	}

	return nil
}

// ReportDoubleSign reports evidence of a validator double signing
func (c *ConsensusClient) ReportDoubleSign(validator common.Address, blockHash string) error {
	evidence := EvidenceData{
		Validator:    validator,
		EvidenceType: DoubleSignEvidence,
		BlockHash:    blockHash,
		Reason:       "Validator signed multiple blocks at the same height",
	}

	msg := ConsensusMessage{
		Type:      DoubleSignEvidence,
		Sender:    c.selfAddress,
		Evidence:  &evidence,
		Timestamp: time.Now(),
	}

	// Record the double sign in the consensus mechanism
	c.Consensus.RecordDoubleSign(validator)

	return c.publishMessage(msg)
}

// ReportInvalidBlock reports evidence of a validator proposing an invalid block
func (c *ConsensusClient) ReportInvalidBlock(validator common.Address, blockHash string, reason string) error {
	evidence := EvidenceData{
		Validator:    validator,
		EvidenceType: InvalidBlockEvidence,
		BlockHash:    blockHash,
		Reason:       reason,
	}

	msg := ConsensusMessage{
		Type:      InvalidBlockEvidence,
		Sender:    c.selfAddress,
		Evidence:  &evidence,
		Timestamp: time.Now(),
	}

	// Record the invalid transaction in the consensus mechanism
	c.Consensus.RecordInvalidTransaction(validator)

	return c.publishMessage(msg)
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

// ConnectToPeer establishes a connection to a peer
func (c *ConsensusClient) ConnectToPeer(peerAddr string) error {
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

// PeerInfo returns information about the host's peer ID and addresses
func (c *ConsensusClient) PeerInfo() string {
	hostID := c.host.ID()
	addrs := c.host.Addrs()

	var peerAddrs []string
	for _, addr := range addrs {
		peerAddrs = append(peerAddrs, fmt.Sprintf("%s/p2p/%s", addr.String(), hostID.String()))
	}

	return fmt.Sprintf("PeerID: %s\nAddresses: %v", hostID.String(), peerAddrs)
}

// Peers returns a list of connected peers
func (c *ConsensusClient) Peers() []peer.ID {
	return c.host.Network().Peers()
}

// handleMessages processes incoming messages from the subscription
func (c *ConsensusClient) handleMessages() {
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

		// Deserialize the message
		var consensusMsg ConsensusMessage
		if err := json.Unmarshal(msg.Data, &consensusMsg); err != nil {
			c.logger.WithError(err).Error("Failed to unmarshal consensus message")
			continue
		}

		// Check if we've seen this message before (deduplication)
		messageID := fmt.Sprintf("%s-%d-%s", consensusMsg.Sender.Hex(), consensusMsg.Type, consensusMsg.Timestamp)
		c.seenMutex.RLock()
		seen := c.seenMessages[messageID]
		c.seenMutex.RUnlock()

		if seen {
			continue
		}

		// Mark as seen
		c.seenMutex.Lock()
		c.seenMessages[messageID] = true
		c.seenMutex.Unlock()

		// Process message based on type
		c.processMessage(consensusMsg)
	}
}

// processMessage handles a consensus message based on its type
func (c *ConsensusClient) processMessage(msg ConsensusMessage) {
	switch msg.Type {
	case BlockProposal:
		if msg.BlockData != nil {
			c.logger.WithFields(logrus.Fields{
				"sender":    msg.Sender.Hex(),
				"blockHash": msg.BlockData.Hash,
			}).Info("Received block proposal")

			// Record block production for the validator
			c.Consensus.RecordBlockProduction(msg.Sender)

			// Validate the block with the execution client if available
			if c.harborClient != nil {
				go func() {
					valid, err := c.ValidateBlockWithExecutionClient(msg.BlockData)
					if err != nil {
						c.logger.WithError(err).Error("Failed to validate block with execution client")
						return
					}

					// Record our local validation result
					c.voteTracker.RecordLocalValidation(msg.BlockData.Hash, valid)

					// Vote on the block based on validation result
					if valid {
						c.logger.WithField("blockHash", msg.BlockData.Hash).Info("Block validation successful, voting to approve")
						if err := c.SubmitVote(msg.BlockData.Hash, true); err != nil {
							c.logger.WithError(err).Error("Failed to submit approval vote")
						}
					} else {
						c.logger.WithField("blockHash", msg.BlockData.Hash).Warn("Block validation failed, voting to reject")
						if err := c.SubmitVote(msg.BlockData.Hash, false); err != nil {
							c.logger.WithError(err).Error("Failed to submit rejection vote")
						}

						// Report the invalid block if validation failed
						reason := "Block failed validation by execution client"
						if err := c.ReportInvalidBlock(msg.Sender, msg.BlockData.Hash, reason); err != nil {
							c.logger.WithError(err).Error("Failed to report invalid block")
						}
					}

					// After recording our own validation, check for misbehaving validators
					c.checkBlockConsensus(msg.BlockData.Hash)
				}()
			} else {
				c.logger.Warn("No execution client available to validate block, skipping validation")
			}

			// Forward to the block proposal channel
			select {
			case c.proposalCh <- msg.BlockData:
			default:
				c.logger.Warn("Block proposal channel full, dropping message")
			}
		}

	case Vote:
		if msg.Vote != nil {
			c.logger.WithFields(logrus.Fields{
				"sender":    msg.Sender.Hex(),
				"validator": msg.Vote.Validator.Hex(),
				"blockHash": msg.Vote.BlockHash,
				"approve":   msg.Vote.Approve,
			}).Info("Received vote")

			// Track the vote for validation monitoring
			c.voteTracker.TrackVote(msg.Vote.BlockHash, msg.Vote.Validator, msg.Vote.Approve)

			// Check for misbehaving validators if we have a local validation result
			_, exists := c.voteTracker.GetLocalValidation(msg.Vote.BlockHash)
			if exists {
				go c.checkBlockConsensus(msg.Vote.BlockHash)
			}

			// Forward to the vote channel
			select {
			case c.voteCh <- msg.Vote:
			default:
				c.logger.Warn("Vote channel full, dropping message")
			}
		}

	case ValidationMissed, DoubleSignEvidence, InvalidBlockEvidence:
		if msg.Evidence != nil {
			c.logger.WithFields(logrus.Fields{
				"sender":       msg.Sender.Hex(),
				"validator":    msg.Evidence.Validator.Hex(),
				"evidenceType": msg.Evidence.EvidenceType,
				"reason":       msg.Evidence.Reason,
			}).Info("Received evidence")

			// Apply the penalty based on evidence type
			switch msg.Evidence.EvidenceType {
			case ValidationMissed:
				c.Consensus.RecordMissedValidation(msg.Evidence.Validator)
			case DoubleSignEvidence:
				c.Consensus.RecordDoubleSign(msg.Evidence.Validator)
			case InvalidBlockEvidence:
				c.Consensus.RecordInvalidTransaction(msg.Evidence.Validator)
			}

			// Forward to the evidence channel
			select {
			case c.evidenceCh <- msg.Evidence:
			default:
				c.logger.Warn("Evidence channel full, dropping message")
			}
		}

	case ValidatorAnnouncement:
		if msg.ValidatorAddress != (common.Address{}) {
			// Process validator announcement
			c.processValidatorAnnouncement(msg.ValidatorAddress, msg.ValidatorStake, msg.ValidatorMetrics, msg.Sender)
		}
	}
}

// checkBlockConsensus checks if a block has reached consensus and identifies validators who voted incorrectly
func (c *ConsensusClient) checkBlockConsensus(blockHash string) {
	// Check if we have a local validation result
	localValid, exists := c.voteTracker.GetLocalValidation(blockHash)
	if !exists {
		// We haven't validated this block yet
		return
	}

	// Identify validators who voted differently than our local validation
	misbehavingValidators := c.voteTracker.IdentifyMisbehavingValidators(blockHash)

	// If we found misbehaving validators, report them
	if len(misbehavingValidators) > 0 {
		for validator, vote := range misbehavingValidators {
			reason := fmt.Sprintf("Validator voted %v when our local validation was %v",
				vote, localValid)

			c.logger.WithFields(logrus.Fields{
				"validator":   validator.Hex(),
				"blockHash":   blockHash,
				"theirVote":   vote,
				"ourValidity": localValid,
			}).Warn("Detected validator voting against local validation result")

			// Report the validator for submitting an invalid vote
			if err := c.ReportInvalidBlock(validator, blockHash, reason); err != nil {
				c.logger.WithError(err).Error("Failed to report validator for incorrect vote")
			}
		}
	}

	if localValid {
		c.logger.WithField("blockHash", blockHash).Info("Block locally validated as valid")
	} else {
		c.logger.WithField("blockHash", blockHash).Info("Block locally validated as invalid")
	}
}

// publishMessage serializes and publishes a message to the topic
func (c *ConsensusClient) publishMessage(msg ConsensusMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Check if the topic is nil (could happen during shutdown or in test contexts)
	if c.topic == nil {
		// In test environments, it's common for the topic to be nil
		// Instead of returning an error, just log it and continue
		c.logger.WithFields(logrus.Fields{
			"type":   msg.Type,
			"sender": msg.Sender.Hex(),
		}).Debug("Cannot publish message: topic is nil")
		return nil
	}

	if err := c.topic.Publish(c.ctx, data); err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"type":   msg.Type,
		"sender": msg.Sender.Hex(),
	}).Debug("Published message")

	return nil
}

// runValidatorSelectionLoop periodically selects a validator for the next block
func (c *ConsensusClient) runValidatorSelectionLoop() {
	ticker := time.NewTicker(c.Consensus.GetSlotDuration())
	defer ticker.Stop()

	var lastSelectedValidator common.Address
	var lastSelectionTime time.Time
	var missedValidations map[common.Address]time.Time = make(map[common.Address]time.Time)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			validator := c.Consensus.SelectValidator()

			// Check if the previously selected validator should have produced a block
			if lastSelectedValidator != (common.Address{}) &&
				lastSelectedValidator != c.selfAddress { // Don't report ourselves

				// Check if we're past the expected block time and haven't received a block
				timeElapsed := time.Since(lastSelectionTime)
				if timeElapsed > c.Consensus.GetSlotDuration() {
					// If we previously marked this validator, check if it's time to report
					if lastMarked, exists := missedValidations[lastSelectedValidator]; exists {
						// If it's been more than one full slot since we marked them, report
						if time.Since(lastMarked) >= c.Consensus.GetSlotDuration() {
							c.ReportMissedValidation(lastSelectedValidator)
							c.logger.WithFields(logrus.Fields{
								"validator": lastSelectedValidator.Hex(),
								"elapsed":   timeElapsed,
							}).Info("Reporting validator for missed block production")

							// Remove from our tracking map after reporting
							delete(missedValidations, lastSelectedValidator)
						}
					} else {
						// Mark this validator as potentially missing their slot
						missedValidations[lastSelectedValidator] = time.Now()
					}
				}
			}

			// Update for the next cycle
			lastSelectedValidator = validator
			lastSelectionTime = time.Now()

			// Check if we are the selected validator
			if validator == c.selfAddress {
				c.logger.WithField("validator", validator.Hex()).Info("We are the selected validator for this slot")

				// Request a block from the execution client
				if c.harborClient != nil {
					go func() {
						block, err := c.RequestBlockFromExecutionClient()
						if err != nil {
							c.logger.WithError(err).Error("Failed to get block from execution client")
							return
						}

						// Propose the block to the network
						if err := c.ProposeBlock(block); err != nil {
							c.logger.WithError(err).Error("Failed to propose block")
							return
						}

						c.logger.WithFields(logrus.Fields{
							"blockHash":  block.Hash,
							"blockIndex": block.Index,
							"txCount":    len(block.Transactions),
						}).Info("Successfully proposed block to the network")
					}()
				} else {
					c.logger.Warn("No execution client available to create block")
				}
			} else {
				c.logger.WithField("validator", validator.Hex()).Info("Selected validator for this slot")
			}
		}
	}
}

// discoveryNotifee is a struct for handling peer discovery notifications
type discoveryNotifee struct {
	c *ConsensusClient
}

// HandlePeerFound is called when a new peer is discovered
func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	n.c.logger.WithFields(logrus.Fields{
		"peerID": pi.ID.String(),
		"addrs":  pi.Addrs,
	}).Info("Discovered new peer")

	if err := n.c.host.Connect(n.c.ctx, pi); err != nil {
		n.c.logger.WithError(err).WithField("peer", pi.ID).Warn("Failed to connect to discovered peer")
	}
}

// GarbageCollectSeenMessages removes old seen messages to prevent memory leaks
func (c *ConsensusClient) GarbageCollectSeenMessages(interval time.Duration) {
	// Run garbage collection periodically
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.seenMutex.Lock()
			// Simple strategy: just clear the map every 5 minutes
			// In a real system, you might want to be more sophisticated
			c.seenMessages = make(map[string]bool)
			c.seenMutex.Unlock()

			c.logger.Debug("Garbage collected seen messages cache")
		}
	}
}

// GetValidatorAddress returns the validator address used by this client
func (c *ConsensusClient) GetValidatorAddress() common.Address {
	return c.selfAddress
}

// AnnounceValidator broadcasts this node's validator status to the network
func (c *ConsensusClient) AnnounceValidator() error {
	// Get current stake amount
	stake := c.Consensus.GetValidatorStake(c.selfAddress)

	// Only announce if we have sufficient stake
	if stake == 0 {
		return fmt.Errorf("not a validator, insufficient stake to announce")
	}

	// Get validator metrics
	metrics := c.Consensus.GetValidatorMetrics(c.selfAddress)
	if metrics == nil {
		// Create default metrics if none exist
		metrics = &consensus.ValidationMetrics{
			Status:         consensus.StatusActive,
			LastActiveTime: time.Now(),
		}
	}

	// Record our own validator as seen
	c.recordValidatorSeen(c.selfAddress)

	// Create and publish announcement message
	msg := ConsensusMessage{
		Type:             ValidatorAnnouncement,
		Sender:           c.selfAddress,
		ValidatorAddress: c.selfAddress,
		ValidatorStake:   stake,
		ValidatorMetrics: metrics,
		Timestamp:        time.Now(),
	}

	return c.publishMessage(msg)
}

// runValidatorAnnouncementLoop periodically announces validator status
func (c *ConsensusClient) runValidatorAnnouncementLoop() {
	// Announce once immediately
	if err := c.AnnounceValidator(); err != nil {
		c.logger.WithError(err).Debug("Failed to announce validator status")
	}

	// Then announce periodically
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				if err := c.AnnounceValidator(); err != nil {
					c.logger.WithError(err).Debug("Failed to announce validator status")
				}
			}
		}
	}()

	c.logger.Debug("Started validator announcement loop")
}

// processValidatorAnnouncement handles validator announcements from other nodes
func (c *ConsensusClient) processValidatorAnnouncement(validatorAddress common.Address, stake uint64, metrics *consensus.ValidationMetrics, sender common.Address) {
	if validatorAddress == (common.Address{}) {
		c.logger.Error("Received empty validator announcement")
		return
	}

	c.logger.WithFields(logrus.Fields{
		"validator": validatorAddress.Hex(),
		"stake":     stake,
		"status":    metrics.Status.String(),
		"sender":    sender.Hex(),
	}).Info("Received validator announcement")

	// Record when this validator was last seen
	c.recordValidatorSeen(validatorAddress)

	// In a production system, we would:
	// 1. Verify the signature to confirm ownership
	// 2. Check if the stake matches what's recorded on-chain

	// For this simulator, we'll trust the announcement and update our local consensus

	// Add or update the validator in our local consensus
	// Note: we're using the announced stake directly, but in a real system
	// this would be verified against an on-chain record
	c.Consensus.Deposit(validatorAddress, stake)

	// Update status if needed
	currentStatus := c.Consensus.GetValidatorStatus(validatorAddress)

	// Only update status if the announced status is different
	if currentStatus != metrics.Status {
		switch metrics.Status {
		case consensus.StatusProbation:
			if currentStatus != consensus.StatusProbation {
				// Set validator on probation (simplified)
				for i := 0; i < int(c.Consensus.GetProbationThreshold()); i++ {
					c.Consensus.RecordMissedValidation(validatorAddress)
				}
			}
		case consensus.StatusSlashed:
			if currentStatus != consensus.StatusSlashed {
				c.Consensus.SlashValidator(validatorAddress, "Reported as slashed by peer")
			}
		}
	}
}

// recordValidatorSeen updates the last time a validator was seen
func (c *ConsensusClient) recordValidatorSeen(validator common.Address) {
	c.lastSeenMutex.Lock()
	defer c.lastSeenMutex.Unlock()

	c.lastSeenValidators[validator] = time.Now()
}

// monitorOfflineValidators periodically checks for validators that haven't been seen recently
func (c *ConsensusClient) monitorOfflineValidators() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkOfflineValidators()
		}
	}
}

// checkOfflineValidators checks for validators that haven't been seen recently and reports them
func (c *ConsensusClient) checkOfflineValidators() {
	now := time.Now()
	offlineThreshold := now.Add(-c.validatorOfflineThreshold)

	// Get all active validators
	validators := c.Consensus.GetValidatorSet()

	c.lastSeenMutex.RLock()
	for _, validator := range validators {
		// Skip our own address
		if validator == c.selfAddress {
			continue
		}

		lastSeen, exists := c.lastSeenValidators[validator]
		if !exists || lastSeen.Before(offlineThreshold) {
			// This validator hasn't been seen recently
			c.lastSeenMutex.RUnlock() // Unlock before making the call to avoid deadlock

			// Get current status to avoid unnecessary reports
			status := c.Consensus.GetValidatorStatus(validator)
			if status == consensus.StatusActive {
				// Report the missed validation
				c.ReportMissedValidation(validator)

				c.logger.WithFields(logrus.Fields{
					"validator": validator.Hex(),
					"lastSeen":  lastSeen,
				}).Info("Reporting validator as offline due to missed announcements")
			}

			c.lastSeenMutex.RLock() // Lock again to continue iteration
		}
	}
	c.lastSeenMutex.RUnlock()
}

// RequestBlockFromExecutionClient requests the execution client to create a new block
// from its transaction pool when this node is selected as the validator
func (c *ConsensusClient) RequestBlockFromExecutionClient() (*blockchain.Block, error) {
	// Check if we have a harbor client
	if c.harborClient == nil {
		return nil, fmt.Errorf("no Harbor client available")
	}

	c.logger.Info("Requesting block creation via Harbor API")

	// Get the last block hash to build upon (if any)
	var prevBlockHash string
	// In a real implementation, you would store and track the latest blocks
	// This is a simplified implementation

	// Request block creation with a maximum of 100 transactions
	// In a real implementation, you might want to configure this
	maxTransactions := uint32(100)

	block, err := c.harborClient.RequestBlockCreation(c.ctx, c.selfAddress, prevBlockHash, maxTransactions)
	if err != nil {
		return nil, fmt.Errorf("failed to request block via Harbor API: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"blockHash":  block.Hash,
		"blockIndex": block.Index,
		"txCount":    len(block.Transactions),
	}).Info("Successfully received block from execution client")

	return block, nil
}

// ValidateBlockWithExecutionClient sends a block to the execution client for validation
func (c *ConsensusClient) ValidateBlockWithExecutionClient(block *blockchain.Block) (bool, error) {
	// Check if we have a harbor client
	if c.harborClient == nil {
		return false, fmt.Errorf("no Harbor client available")
	}

	c.logger.WithFields(logrus.Fields{
		"blockHash":  block.Hash,
		"blockIndex": block.Index,
	}).Info("Sending block to execution client for validation via Harbor API")

	valid, err := c.harborClient.ValidateBlock(c.ctx, block)
	if err != nil {
		return false, fmt.Errorf("failed to validate block via Harbor API: %w", err)
	}

	if !valid {
		c.logger.WithField("blockHash", block.Hash).Warn("Block validation failed at execution client")
		return false, nil
	}

	c.logger.WithField("blockHash", block.Hash).Info("Block successfully validated by execution client")
	return true, nil
}

// runVoteTrackerCleanup periodically cleans up stale votes to prevent memory leaks
func (c *ConsensusClient) runVoteTrackerCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.cleanupStaleVotes()
		}
	}
}

// cleanupStaleVotes removes vote tracking for blocks that are too old
func (c *ConsensusClient) cleanupStaleVotes() {
	c.voteTracker.mutex.Lock()
	defer c.voteTracker.mutex.Unlock()

	// In this simplified implementation, we'll just limit the number of tracked blocks
	// to prevent memory leaks
	maxTrackedBlocks := 1000

	if len(c.voteTracker.votes) > maxTrackedBlocks {
		// Get a list of all tracked block hashes
		blockHashes := make([]string, 0, len(c.voteTracker.votes))
		for hash := range c.voteTracker.votes {
			blockHashes = append(blockHashes, hash)
		}

		// Remove the oldest half of the blocks
		blocksToRemove := len(blockHashes) - maxTrackedBlocks/2
		for i := 0; i < blocksToRemove && i < len(blockHashes); i++ {
			hash := blockHashes[i]
			delete(c.voteTracker.votes, hash)
			delete(c.voteTracker.localValidations, hash)

			c.logger.WithField("blockHash", hash).Debug("Cleaned up stale vote tracking for old block")
		}
	}
}

// ValidatorVotingStats contains statistics about a validator's voting behavior
type ValidatorVotingStats struct {
	// Total number of votes cast by the validator
	TotalVotes int

	// Number of votes that matched our local validation
	CorrectVotes int

	// Number of votes that contradicted our local validation
	IncorrectVotes int

	// Accuracy percentage (correct votes / total votes)
	Accuracy float64
}

// AnalyzeValidatorBehavior analyzes voting behavior of validators and returns statistics
func (c *ConsensusClient) AnalyzeValidatorBehavior() map[common.Address]*ValidatorVotingStats {
	stats := make(map[common.Address]*ValidatorVotingStats)

	// Lock the vote tracker to prevent concurrent modification
	c.voteTracker.mutex.RLock()
	defer c.voteTracker.mutex.RUnlock()

	// Process each block that we have locally validated
	for blockHash, localValidation := range c.voteTracker.localValidations {
		if votes, exists := c.voteTracker.votes[blockHash]; exists {
			// Check each validator's vote
			for validator, vote := range votes {
				// Skip our own votes
				if validator == c.selfAddress {
					continue
				}

				// Initialize stats for this validator if needed
				if _, exists := stats[validator]; !exists {
					stats[validator] = &ValidatorVotingStats{}
				}

				// Update statistics
				stats[validator].TotalVotes++
				if vote == localValidation {
					stats[validator].CorrectVotes++
				} else {
					stats[validator].IncorrectVotes++
				}
			}
		}
	}

	// Calculate accuracy percentages
	for _, validatorStats := range stats {
		if validatorStats.TotalVotes > 0 {
			validatorStats.Accuracy = float64(validatorStats.CorrectVotes) / float64(validatorStats.TotalVotes) * 100.0
		}
	}

	return stats
}

// GetMisbehavingValidators returns a list of validators whose voting accuracy is below the threshold
func (c *ConsensusClient) GetMisbehavingValidators(minVotes int, accuracyThreshold float64) []common.Address {
	stats := c.AnalyzeValidatorBehavior()
	misbehaving := make([]common.Address, 0)

	for validator, validatorStats := range stats {
		// Only consider validators with enough votes to be statistically significant
		if validatorStats.TotalVotes >= minVotes {
			// If accuracy is below threshold, consider them misbehaving
			if validatorStats.Accuracy < accuracyThreshold {
				misbehaving = append(misbehaving, validator)

				c.logger.WithFields(logrus.Fields{
					"validator":      validator.Hex(),
					"totalVotes":     validatorStats.TotalVotes,
					"correctVotes":   validatorStats.CorrectVotes,
					"incorrectVotes": validatorStats.IncorrectVotes,
					"accuracy":       validatorStats.Accuracy,
				}).Warn("Identified potentially misbehaving validator")
			}
		}
	}

	return misbehaving
}

// runValidatorBehaviorMonitoring periodically checks for misbehaving validators
func (c *ConsensusClient) runValidatorBehaviorMonitoring(interval time.Duration) {
	// Wait a bit before the first check to gather some data
	time.Sleep(interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.monitorValidatorBehavior()
		}
	}
}

// monitorValidatorBehavior analyzes validator voting behavior and penalizes consistently misbehaving validators
func (c *ConsensusClient) monitorValidatorBehavior() {
	// Minimum number of votes required to consider a validator's behavior
	minVotes := 5

	// Accuracy threshold (percentage) below which we consider a validator misbehaving
	accuracyThreshold := 70.0

	// Get misbehaving validators
	misbehaving := c.GetMisbehavingValidators(minVotes, accuracyThreshold)

	if len(misbehaving) > 0 {
		c.logger.WithField("count", len(misbehaving)).Info("Identified misbehaving validators")

		// Analyze and report each misbehaving validator
		for _, validator := range misbehaving {
			// Get current status to avoid unnecessary reports
			status := c.Consensus.GetValidatorStatus(validator)

			// Only take action if they're not already penalized
			if status == consensus.StatusActive {
				// For validators with very poor accuracy, we might want to escalate
				// to a more severe penalty sooner
				stats := c.AnalyzeValidatorBehavior()[validator]

				if stats.Accuracy < 50.0 && stats.TotalVotes >= 10 {
					// Severe misbehavior - consider slashing
					reason := fmt.Sprintf("Validator consistently voted incorrectly (%.1f%% accuracy across %d votes)",
						stats.Accuracy, stats.TotalVotes)

					c.logger.WithFields(logrus.Fields{
						"validator": validator.Hex(),
						"accuracy":  stats.Accuracy,
						"votes":     stats.TotalVotes,
					}).Warn("Slashing validator for consistent incorrect voting")

					// Slash the validator
					c.Consensus.SlashValidator(validator, reason)
				} else {
					// Less severe - put on probation by recording multiple missed validations
					for i := 0; i < int(c.Consensus.GetProbationThreshold()); i++ {
						c.Consensus.RecordMissedValidation(validator)
					}

					c.logger.WithFields(logrus.Fields{
						"validator": validator.Hex(),
						"accuracy":  stats.Accuracy,
						"votes":     stats.TotalVotes,
					}).Warn("Putting validator on probation for incorrect voting")
				}
			}
		}
	}
}
