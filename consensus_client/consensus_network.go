package consensus_client

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/consensus"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/libp2p/go-libp2p/core/peer"
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

// Peers returns a list of connected peers
func (c *ConsensusClient) Peers() []peer.ID {
	return c.host.Network().Peers()
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
