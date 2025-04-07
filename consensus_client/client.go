// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/consensus"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
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

// ConsensusClient manages the p2p network for consensus algorithms
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
}

// NewConsensusClient creates a new consensus client with a randomly generated validator address
// and an internal Proof of Stake consensus instance
func NewConsensusClient(
	listenAddr string,
	initialStake uint64,
	logger *logrus.Logger,
) (*ConsensusClient, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Generate a random validator address
	randBytes := make([]byte, 20)
	if _, err := rand.Read(randBytes); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to generate random address: %w", err)
	}
	selfAddress := common.BytesToAddress(randBytes)

	// Initialize a logger if not provided
	if logger == nil {
		logger = logrus.New()
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
		logger.SetLevel(logrus.InfoLevel)
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
				// Signal to the application that we should propose a block
				// TODO: Make a call to the Execution Client to get the latest block via gRPC
				// This would typically be handled by application-specific logic
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
