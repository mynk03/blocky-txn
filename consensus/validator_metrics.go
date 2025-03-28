package consensus

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// ValidatorStatus represents the current status of a validator
type ValidatorStatus int

const (
	// StatusActive means the validator is in good standing
	StatusActive ValidatorStatus = iota + 1 // Start from 1 instead of 0
	// StatusProbation means the validator has been flagged for minor issues
	StatusProbation
	// StatusSlashed means the validator has been severely penalized
	StatusSlashed
)

// ValidationMetrics tracks a validator's performance metrics
type ValidationMetrics struct {
	BlocksProposed      uint64
	BlocksValidated     uint64
	MissedValidations   uint64
	DoubleSignings      uint64
	InvalidTransactions uint64
	LastActiveTime      time.Time
	Status              ValidatorStatus
	SlashingPenalty     int // Current cumulative slashing penalty
}

// CalculateValidatorReward calculates the actual reward for a specific validator
// based on their performance and status
func (pos *ProofOfStake) CalculateValidatorReward(validator common.Address) int {
	pos.mu.RLock()
	defer pos.mu.RUnlock()

	baseReward := pos.baseReward
	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		return 0 // No reward if validator doesn't exist
	}

	// Apply status multiplier
	statusMultiplier := pos.rewardMultipliers[metrics.Status]
	if metrics.Status == StatusSlashed {
		return 0 // No rewards for slashed validators
	}

	// Calculate consecutive block bonus (capped at 25%)
	consecutiveBonus := float64(0)
	if metrics.BlocksValidated > 0 {
		consecutiveBonus = min(float64(metrics.BlocksValidated)*pos.consecutiveBonus, 0.25)
	}

	// Calculate stake-weighted component
	stakeWeight := float64(1.0)
	if pos.totalStake > 0 && pos.validators[validator] > 0 {
		stakeWeight = float64(pos.validators[validator]) / float64(pos.totalStake)
		stakeWeight = 0.5 + (stakeWeight * 0.5) // 50% base + 50% stake-weighted
	}

	// Calculate final reward with all multipliers
	finalReward := float64(baseReward) * statusMultiplier * (1 + consecutiveBonus) * stakeWeight

	return int(finalReward)
}

// RecordBlockProduction records that a validator successfully produced a block
func (pos *ProofOfStake) RecordBlockProduction(validator common.Address) {
	pos.mu.Lock()
	defer pos.mu.Unlock()

	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		// Initialize metrics if this is first activity
		metrics = &ValidationMetrics{
			Status:         StatusActive,
			LastActiveTime: time.Now(),
		}
		pos.validatorMetrics[validator] = metrics
	}

	metrics.BlocksProposed++
	metrics.BlocksValidated++
	metrics.LastActiveTime = time.Now()
}

// RecordMissedValidation records that a validator missed their validation slot
func (pos *ProofOfStake) RecordMissedValidation(validator common.Address) {
	pos.mu.Lock()
	defer pos.mu.Unlock()

	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		return // Can't penalize non-existent validator
	}

	metrics.MissedValidations++

	// Apply escalating penalties based on missed validations
	if metrics.MissedValidations >= pos.slashThreshold && metrics.Status != StatusSlashed {
		// Set status to StatusSlashed
		metrics.Status = StatusSlashed
	} else if metrics.MissedValidations >= pos.probationThreshold && metrics.Status == StatusActive {
		// Set status to StatusProbation
		metrics.Status = StatusProbation
	}
}

// RecordDoubleSign records evidence of double signing (a serious violation)
func (pos *ProofOfStake) RecordDoubleSign(validator common.Address) {
	pos.mu.Lock()
	defer pos.mu.Unlock()

	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		return // Can't penalize non-existent validator
	}

	metrics.DoubleSignings++

	// Double signing is a major violation - immediate slash if multiple occurrences
	if metrics.DoubleSignings > 1 {
		pos.SlashValidator(validator, "Multiple double signing violations")
	} else {
		// Just set to probation for first offense
		metrics.Status = StatusProbation
	}
}

// RecordInvalidTransaction records when a validator includes invalid transactions
func (pos *ProofOfStake) RecordInvalidTransaction(validator common.Address) {
	pos.mu.Lock()
	defer pos.mu.Unlock()

	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		return
	}

	metrics.InvalidTransactions++

	// Apply penalties based on number of invalid transactions
	if metrics.InvalidTransactions >= pos.slashThreshold {
		// Set status to StatusSlashed
		metrics.Status = StatusSlashed
	} else if metrics.InvalidTransactions >= pos.probationThreshold && metrics.Status == StatusActive {
		// Set status to StatusProbation
		metrics.Status = StatusProbation
	}
}

// SlashValidator penalizes a validator by taking a percentage of their stake
func (pos *ProofOfStake) SlashValidator(validator common.Address, reason string) {
	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		return
	}

	metrics.Status = StatusSlashed

	// The actual slashing of stake happens during withdrawal
	// This avoids having to immediately realize the slashing
}

// ResetValidator resets a validator's metrics and status
// Typically used after corrective action has been taken
func (pos *ProofOfStake) ResetValidator(validator common.Address) {
	pos.mu.Lock()
	defer pos.mu.Unlock()

	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		return
	}

	// Reset metrics but preserve historical data
	metrics.Status = StatusActive
	metrics.MissedValidations = 0
	metrics.InvalidTransactions = 0
}

// GetValidatorStatus returns the current status of a validator
func (pos *ProofOfStake) GetValidatorStatus(validator common.Address) ValidatorStatus {
	pos.mu.RLock()
	defer pos.mu.RUnlock()

	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		return StatusActive // Default for new validators
	}

	return metrics.Status
}

// GetValidatorMetrics returns the performance metrics for a validator
func (pos *ProofOfStake) GetValidatorMetrics(validator common.Address) *ValidationMetrics {
	pos.mu.RLock()
	defer pos.mu.RUnlock()

	metrics, exists := pos.validatorMetrics[validator]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modifications
	metricsCopy := *metrics
	return &metricsCopy
}
