// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/consensus"
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

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
	return c.publishMessage(msg)
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
	return &discoveryNotifee{c: c}
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
	c.processValidatorAnnouncement(validator, stake, metrics, sender)
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
	c.runValidatorBehaviorMonitoring(interval)
}

// IdentifyMisbehavingValidatorsForTesting allows tests to call the IdentifyMisbehavingValidators method directly
func (c *ConsensusClient) IdentifyMisbehavingValidatorsForTesting(blockHash string) map[common.Address]bool {
	return c.voteTracker.IdentifyMisbehavingValidators(blockHash)
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
