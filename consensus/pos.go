// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus

import (
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// ProofOfStake implements a simple Proof of Stake consensus algorithm
type ProofOfStake struct {
	validators      map[common.Address]int // map of validator addresses to their stakes
	validatorsList  []common.Address       // list of validator addresses for easier selection
	totalStake      int                    // total stake in the system
	slotDuration    time.Duration          // duration of each validation slot
	minStake        int                    // minimum stake required to become a validator
	mu              sync.RWMutex           // for thread safety
	baseReward      int                    // base reward for validating a block
	lastValidatorID int                    // last selected validator (for round-robin option)
	randao          *rand.Rand             // random number generator for validator selection
}

// NewProofOfStake creates a new Proof of Stake consensus instance
func NewProofOfStake(slotDuration time.Duration, minStake int, baseReward int) *ProofOfStake {
	return &ProofOfStake{
		validators:     make(map[common.Address]int),
		validatorsList: []common.Address{},
		totalStake:     0,
		slotDuration:   slotDuration,
		minStake:       minStake,
		baseReward:     baseReward,
		randao:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// SelectValidator selects the next block validator based on stake weight
func (pos *ProofOfStake) SelectValidator() common.Address {
	pos.mu.RLock()
	defer pos.mu.RUnlock()

	if len(pos.validatorsList) == 0 {
		return common.Address{} // Return empty address if no validators
	}

	// Weighted random selection based on stake
	// This gives validators with more stake a higher probability of being selected
	if pos.totalStake <= 0 {
		// If no stake in the system (should not happen), use round-robin
		pos.lastValidatorID = (pos.lastValidatorID + 1) % len(pos.validatorsList)
		return pos.validatorsList[pos.lastValidatorID]
	}

	// Generate a random number between 0 and totalStake
	target := pos.randao.Intn(pos.totalStake)

	// Find the validator whose stake range contains the target
	current := 0
	for _, validator := range pos.validatorsList {
		current += pos.validators[validator]
		if target < current {
			return validator
		}
	}

	// Fallback (should not reach here under normal circumstances)
	return pos.validatorsList[0]
}

// GetReward calculates the reward for the validator/miner
func (pos *ProofOfStake) GetReward() int {
	return pos.baseReward
}

// Deposit deposits a validator's stake
func (pos *ProofOfStake) Deposit(validator common.Address, amount int) {
	pos.mu.Lock()
	defer pos.mu.Unlock()

	// If this is a new validator and they have at least the minimum stake
	if _, exists := pos.validators[validator]; !exists {
		if amount >= pos.minStake {
			pos.validators[validator] = amount
			pos.validatorsList = append(pos.validatorsList, validator)
			pos.totalStake += amount
		}
	} else {
		// Existing validator adding more stake
		pos.validators[validator] += amount
		pos.totalStake += amount
	}
}

// Withdraw withdraws a validator's stake
func (pos *ProofOfStake) Withdraw(validator common.Address, amount int) {
	pos.mu.Lock()
	defer pos.mu.Unlock()

	if stake, exists := pos.validators[validator]; exists {
		if amount > stake {
			amount = stake // Can't withdraw more than what's staked
		}

		pos.validators[validator] -= amount
		pos.totalStake -= amount

		// If validator's stake falls below minimum, remove them from validator set
		if pos.validators[validator] < pos.minStake {
			delete(pos.validators, validator)

			// Remove from validatorsList
			for i, v := range pos.validatorsList {
				if v == validator {
					pos.validatorsList = append(pos.validatorsList[:i], pos.validatorsList[i+1:]...)
					break
				}
			}
		}
	}
}

// GetValidatorStake returns the stake of a validator
func (pos *ProofOfStake) GetValidatorStake(validator common.Address) int {
	pos.mu.RLock()
	defer pos.mu.RUnlock()

	return pos.validators[validator]
}

// GetValidatorSet returns the current validator set
func (pos *ProofOfStake) GetValidatorSet() []common.Address {
	pos.mu.RLock()
	defer pos.mu.RUnlock()

	// Return a copy to prevent external modifications
	result := make([]common.Address, len(pos.validatorsList))
	copy(result, pos.validatorsList)

	return result
}

// GetSlotDuration returns the duration of a slot
func (pos *ProofOfStake) GetSlotDuration() time.Duration {
	return pos.slotDuration
}
