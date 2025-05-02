// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package testutils

import (
	"blockchain-simulator/internal/blockchain"
	"blockchain-simulator/internal/consensus"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
)

// VoteTracker tracks votes for blocks
type VoteTracker struct {
	mutex            sync.RWMutex
	votes            map[string]map[common.Address]bool
	localValidations map[string]bool
}

// NewVoteTracker creates a new VoteTracker
func NewVoteTracker() *VoteTracker {
	return &VoteTracker{
		votes:            make(map[string]map[common.Address]bool),
		localValidations: make(map[string]bool),
	}
}

// RecordLocalValidation records a local validation result for a block
func (v *VoteTracker) RecordLocalValidation(blockHash string, isValid bool) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	v.localValidations[blockHash] = isValid
}

// TrackVote tracks a vote for a block
func (v *VoteTracker) TrackVote(blockHash string, validator common.Address, approve bool) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	if v.votes[blockHash] == nil {
		v.votes[blockHash] = make(map[common.Address]bool)
	}
	v.votes[blockHash][validator] = approve
}

// IdentifyMisbehavingValidators identifies validators that have voted against the local validation result
func (v *VoteTracker) IdentifyMisbehavingValidators(blockHash string) map[common.Address]bool {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	misbehaving := make(map[common.Address]bool)
	localValid, exists := v.localValidations[blockHash]
	if !exists {
		return misbehaving
	}
	for validator, vote := range v.votes[blockHash] {
		if vote != localValid {
			misbehaving[validator] = true
		}
	}
	return misbehaving
}

// ExecutionClient is an interface for the execution client
type ExecutionClient interface {
	RequestBlockCreation(ctx context.Context, validatorAddress common.Address, maxTransactions uint32) (*blockchain.Block, error)
	ValidateBlock(ctx context.Context, block *blockchain.Block) (bool, error)
	Close() error
}

// EvidenceData represents evidence of validator misbehavior
type EvidenceData struct {
	Validator common.Address
	Reason    string
}

// VoteData represents a vote for a block
type VoteData struct {
	BlockHash string
	Validator common.Address
	Approve   bool
}

// ConsensusMessage represents a message in the consensus protocol
type ConsensusMessage struct {
	Type      string
	BlockHash string
	Validator common.Address
	Approve   bool
}

func (m *ConsensusMessage) String() string {
	return fmt.Sprintf("%s:%s:%s:%v", m.Type, m.BlockHash, m.Validator.Hex(), m.Approve)
}

// MessageType represents the type of a consensus message
type MessageType int

const (
	BlockProposal MessageType = iota
	Vote
	Evidence
)

// ConsensusClient is a test helper type that provides testing methods for the consensus client
type ConsensusClient struct {
	host               host.Host
	topic              *pubsub.Topic
	ctx                context.Context
	logger             *logrus.Logger
	Consensus          consensus.ConsensusAlgorithm
	lastSeenMutex      sync.RWMutex
	lastSeenValidators map[common.Address]time.Time
	voteTracker        *VoteTracker
	voteCh             chan *VoteData
	selfAddress        common.Address
	seenMessages       map[string]bool
	seenMutex          sync.RWMutex
	harborClient       ExecutionClient
	proposalCh         chan *blockchain.Block
	evidenceCh         chan *EvidenceData
	discovery          *pubsub.PubSub
}

// SetVoteChannelForTesting allows tests to send a vote directly to the vote channel
func (c *ConsensusClient) SetVoteChannelForTesting(vote *VoteData) {
	c.voteCh <- vote
}

// RecordLocalValidationForTesting allows tests to record local validation result
func (c *ConsensusClient) RecordLocalValidationForTesting(blockHash string, isValid bool) {
	c.voteTracker.RecordLocalValidation(blockHash, isValid)
}

// TrackVoteForTesting allows tests to track votes
func (c *ConsensusClient) TrackVoteForTesting(blockHash string, validator common.Address, approve bool) {
	c.voteTracker.TrackVote(blockHash, validator, approve)
}

// MonitorValidatorBehaviorForTesting allows tests to call the monitorValidatorBehavior method directly
func (c *ConsensusClient) MonitorValidatorBehaviorForTesting() {
	c.monitorValidatorBehavior()
}

// SetSelfAddress allows tests to set the client's selfAddress
func (c *ConsensusClient) SetSelfAddress(address common.Address) {
	c.selfAddress = address
}

// GetSelfAddressForTesting allows tests to get the client's selfAddress
func (c *ConsensusClient) GetSelfAddressForTesting() common.Address {
	return c.selfAddress
}

// PublishMessageForTesting allows tests to directly call the publishMessage method
func (c *ConsensusClient) PublishMessageForTesting(msg ConsensusMessage) error {
	return c.publishMessage(&msg)
}

// GetTopicForTesting allows tests to get the client's pubsub topic
func (c *ConsensusClient) GetTopicForTesting() *pubsub.Topic {
	return c.topic
}

// SetTopicForTesting allows tests to set the client's pubsub topic
func (c *ConsensusClient) SetTopicForTesting(topic *pubsub.Topic) {
	c.topic = topic
}

// SetSeenMessagesForTesting allows tests to set the seen messages map
func (c *ConsensusClient) SetSeenMessagesForTesting(messages map[string]bool) {
	c.seenMutex.Lock()
	defer c.seenMutex.Unlock()
	c.seenMessages = messages
}

// GetSeenMessagesCountForTesting allows tests to get the count of seen messages
func (c *ConsensusClient) GetSeenMessagesCountForTesting() int {
	c.seenMutex.RLock()
	defer c.seenMutex.RUnlock()
	return len(c.seenMessages)
}

// ClearSeenMessagesForTesting allows tests to clear the seen messages map
func (c *ConsensusClient) ClearSeenMessagesForTesting() {
	c.seenMutex.Lock()
	defer c.seenMutex.Unlock()
	c.seenMessages = make(map[string]bool)
}

// LogDebugForTesting allows tests to log a debug message
func (c *ConsensusClient) LogDebugForTesting(msg string) {
	c.logger.Debug(msg)
}

// SetContextForTesting allows tests to set the client's context
func (c *ConsensusClient) SetContextForTesting(ctx context.Context) {
	c.ctx = ctx
}

// CreateDiscoveryNotifeeForTesting creates a discoveryNotifee for testing
func (c *ConsensusClient) CreateDiscoveryNotifeeForTesting() *discoveryNotifee {
	return &discoveryNotifee{client: c}
}

// GetConsensusForTesting allows tests to get the client's consensus algorithm
func (c *ConsensusClient) GetConsensusForTesting() consensus.ConsensusAlgorithm {
	return c.Consensus
}

// SetConsensusForTesting allows tests to set the client's consensus algorithm
func (c *ConsensusClient) SetConsensusForTesting(consensus consensus.ConsensusAlgorithm) {
	c.Consensus = consensus
}

// ProcessValidatorAnnouncementForTesting allows tests to call the processValidatorAnnouncement method directly
func (c *ConsensusClient) ProcessValidatorAnnouncementForTesting(
	validator common.Address,
	stake uint64,
	metrics *consensus.ValidationMetrics,
	sender common.Address,
) {
	c.processValidatorAnnouncement(validator)
}

// SetHarborClientForTesting allows tests to set the client's harbor client
func (c *ConsensusClient) SetHarborClientForTesting(harborClient ExecutionClient) {
	c.harborClient = harborClient
}

// GetHarborClientForTesting allows tests to get the client's harbor client
func (c *ConsensusClient) GetHarborClientForTesting() ExecutionClient {
	return c.harborClient
}

// SetProposalChannelForTesting allows tests to send a block directly to the proposal channel
func (c *ConsensusClient) SetProposalChannelForTesting(block *blockchain.Block) {
	c.proposalCh <- block
}

// SetEvidenceChannelForTesting allows tests to send evidence directly to the evidence channel
func (c *ConsensusClient) SetEvidenceChannelForTesting(evidence *EvidenceData) {
	c.evidenceCh <- evidence
}

// RecordValidatorSeenForTesting allows tests to call the recordValidatorSeen method directly
func (c *ConsensusClient) RecordValidatorSeenForTesting(validator common.Address) {
	c.recordValidatorSeen(validator)
}

// GetRecordedValidatorsCountForTesting allows tests to get the count of recorded validators
func (c *ConsensusClient) GetRecordedValidatorsCountForTesting() int {
	c.lastSeenMutex.RLock()
	defer c.lastSeenMutex.RUnlock()
	return len(c.lastSeenValidators)
}

// CleanupStaleVotesForTesting allows tests to call the cleanupStaleVotes method directly
func (c *ConsensusClient) CleanupStaleVotesForTesting() {
	c.cleanupStaleVotes()
}

// GetPeersForTesting allows tests to get the peer.ID list for the host
func (c *ConsensusClient) GetPeersForTesting() []peer.ID {
	return c.host.Network().Peers()
}

// RunValidatorBehaviorMonitoringForTesting allows tests to run the validator behavior monitoring with a custom interval
func (c *ConsensusClient) RunValidatorBehaviorMonitoringForTesting(interval time.Duration) {
	c.runValidatorBehaviorMonitoring()
}

// CheckBlockConsensusForTesting allows tests to call the checkBlockConsensus method directly
func (c *ConsensusClient) CheckBlockConsensusForTesting(blockHash string) {
	c.checkBlockConsensus(blockHash)
}

// GetVoteTrackerForTesting allows tests to access the vote tracker for testing purposes
func (c *ConsensusClient) GetVoteTrackerForTesting() *VoteTracker {
	return c.voteTracker
}

// ResetVoteTrackerForTesting resets the vote tracker to an empty state for testing
func (c *ConsensusClient) ResetVoteTrackerForTesting() {
	c.voteTracker = NewVoteTracker()
}

// GetVoteMapSizeForTesting returns the size of the votes map for testing
func (c *ConsensusClient) GetVoteMapSizeForTesting() int {
	c.voteTracker.mutex.RLock()
	defer c.voteTracker.mutex.RUnlock()
	return len(c.voteTracker.votes)
}

// GetLocalValidationMapSizeForTesting returns the size of the localValidations map for testing
func (c *ConsensusClient) GetLocalValidationMapSizeForTesting() int {
	c.voteTracker.mutex.RLock()
	defer c.voteTracker.mutex.RUnlock()
	return len(c.voteTracker.localValidations)
}

// monitorValidatorBehavior monitors the behavior of validators
func (c *ConsensusClient) monitorValidatorBehavior() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.lastSeenMutex.RLock()
			now := time.Now()
			for validator, lastSeen := range c.lastSeenValidators {
				if now.Sub(lastSeen) > 30*time.Second {
					c.logger.Warnf("Validator %s has not been seen for more than 30 seconds", validator.Hex())
				}
			}
			c.lastSeenMutex.RUnlock()
		}
	}
}

// publishMessage publishes a message to the consensus topic
func (c *ConsensusClient) publishMessage(msg *ConsensusMessage) error {
	if c.topic == nil {
		return fmt.Errorf("consensus topic not initialized")
	}
	return c.topic.Publish(c.ctx, []byte(msg.String()))
}

// processValidatorAnnouncement processes a validator announcement
func (c *ConsensusClient) processValidatorAnnouncement(validator common.Address) {
	c.lastSeenMutex.Lock()
	c.lastSeenValidators[validator] = time.Now()
	c.lastSeenMutex.Unlock()
}

// recordValidatorSeen records that a validator was seen
func (c *ConsensusClient) recordValidatorSeen(validator common.Address) {
	c.lastSeenMutex.Lock()
	c.lastSeenValidators[validator] = time.Now()
	c.lastSeenMutex.Unlock()
}

// cleanupStaleVotes cleans up stale votes
func (c *ConsensusClient) cleanupStaleVotes() {
	c.voteTracker.mutex.Lock()
	defer c.voteTracker.mutex.Unlock()

	// Simply clear all votes and validations
	c.voteTracker.votes = make(map[string]map[common.Address]bool)
	c.voteTracker.localValidations = make(map[string]bool)
}

// runValidatorBehaviorMonitoring runs the validator behavior monitoring
func (c *ConsensusClient) runValidatorBehaviorMonitoring() {
	go c.monitorValidatorBehavior()
}

// checkBlockConsensus checks if a block has reached consensus
func (c *ConsensusClient) checkBlockConsensus(blockHash string) bool {
	c.voteTracker.mutex.RLock()
	defer c.voteTracker.mutex.RUnlock()

	votes := c.voteTracker.votes[blockHash]
	if votes == nil {
		return false
	}

	approveCount := 0
	for _, approve := range votes {
		if approve {
			approveCount++
		}
	}

	return approveCount >= len(votes)/2+1
}

// discoveryNotifee handles peer discovery events
type discoveryNotifee struct {
	client *ConsensusClient
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if err := n.client.host.Connect(n.client.ctx, pi); err != nil {
		n.client.logger.Errorf("Failed to connect to peer %s: %v", pi.ID, err)
	}
}

// Network interface implementation
func (n *discoveryNotifee) Connected(net network.Network, conn network.Conn)        {}
func (n *discoveryNotifee) Disconnected(net network.Network, conn network.Conn)     {}
func (n *discoveryNotifee) OpenedStream(net network.Network, stream network.Stream) {}
func (n *discoveryNotifee) ClosedStream(net network.Network, stream network.Stream) {}
func (n *discoveryNotifee) Listen(net network.Network, ma multiaddr.Multiaddr)      {}
func (n *discoveryNotifee) ListenClose(net network.Network, ma multiaddr.Multiaddr) {}

func NewConsensusClient(host host.Host, consensus consensus.ConsensusAlgorithm, logger *logrus.Logger) *ConsensusClient {
	client := &ConsensusClient{
		host:               host,
		Consensus:          consensus,
		logger:             logger,
		proposalCh:         make(chan *blockchain.Block, 100),
		voteCh:             make(chan *VoteData, 100),
		evidenceCh:         make(chan *EvidenceData, 100),
		voteTracker:        NewVoteTracker(),
		seenMessages:       make(map[string]bool),
		seenMutex:          sync.RWMutex{},
		lastSeenMutex:      sync.RWMutex{},
		lastSeenValidators: make(map[common.Address]time.Time),
		ctx:                context.Background(),
	}

	// Initialize pubsub for discovery
	ps, err := pubsub.NewGossipSub(context.Background(), host)
	if err != nil {
		logger.Fatalf("Failed to create pubsub: %v", err)
	}
	client.discovery = ps

	// Initialize discovery service
	discoveryNotifee := &discoveryNotifee{client: client}
	host.Network().Notify(discoveryNotifee)

	return client
}
