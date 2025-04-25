package consensus_client

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

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
