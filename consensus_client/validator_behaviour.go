package consensus_client

import (
	"blockchain-simulator/consensus"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

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
