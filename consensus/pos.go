package consensus

import (
	"math/rand"
	"sync"
	"time"

	"slices"

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

	// Fields for rewards and penalties
	validatorMetrics   map[common.Address]*ValidationMetrics // tracking validator performance
	slashingRate       int                                   // percentage of stake to slash for severe violations
	probationThreshold uint64                                // missed blocks threshold for probation
	slashThreshold     uint64                                // severe violation threshold for slashing
	rewardMultipliers  map[ValidatorStatus]float64           // reward multipliers based on status
	consecutiveBonus   float64                               // bonus multiplier for consecutive validations
}

// NewProofOfStake creates a new Proof of Stake consensus instance
func NewProofOfStake(slotDuration time.Duration, minStake int, baseReward int) *ProofOfStake {
	return &ProofOfStake{
		validators:         make(map[common.Address]int),
		validatorsList:     []common.Address{},
		totalStake:         0,
		slotDuration:       slotDuration,
		minStake:           minStake,
		baseReward:         baseReward,
		randao:             rand.New(rand.NewSource(time.Now().UnixNano())),
		validatorMetrics:   make(map[common.Address]*ValidationMetrics),
		slashingRate:       20, // Default 20% slashing penalty
		probationThreshold: 5,  // 5 missed blocks puts validator on probation
		slashThreshold:     3,  // 3 serious violations result in slashing
		rewardMultipliers: map[ValidatorStatus]float64{
			StatusActive:    1.0,
			StatusProbation: 0.5, // 50% rewards while on probation
			StatusSlashed:   0.0, // No rewards after slashing
		},
		consecutiveBonus: 0.01, // 1% bonus for each consecutive block validated
	}
}

// SelectValidator selects the next block validator based on stake weight
func (pos *ProofOfStake) SelectValidator() common.Address {
	pos.mu.RLock()
	defer pos.mu.RUnlock()

	if len(pos.validatorsList) == 0 {
		return common.Address{} // Return empty address if no validators
	}

	// Filter out slashed validators
	eligibleValidators := []common.Address{}
	eligibleStake := 0

	for _, validator := range pos.validatorsList {
		metrics, hasMetrics := pos.validatorMetrics[validator]
		if !hasMetrics || metrics.Status != StatusSlashed {
			eligibleValidators = append(eligibleValidators, validator)
			eligibleStake += pos.validators[validator]
		}
	}

	if len(eligibleValidators) == 0 {
		return common.Address{} // Return empty address if no eligible validators
	}

	// Weighted random selection based on stake
	if eligibleStake <= 0 {
		// If no stake in the system (should not happen), use round-robin
		pos.lastValidatorID = (pos.lastValidatorID + 1) % len(eligibleValidators)
		return eligibleValidators[pos.lastValidatorID]
	}

	// Generate a random number between 0 and total eligible stake
	target := pos.randao.Intn(eligibleStake)

	// Find the validator whose stake range contains the target
	current := 0
	for _, validator := range eligibleValidators {
		current += pos.validators[validator]
		if target < current {
			return validator
		}
	}

	// Fallback (should not reach here under normal circumstances)
	return eligibleValidators[0]
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

			// Initialize metrics for new validator
			pos.validatorMetrics[validator] = &ValidationMetrics{
				LastActiveTime: time.Now(),
				Status:         StatusActive,
			}
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
		// Check if validator is slashed - apply slashing penalty if applicable
		slashedAmount := 0
		if metrics, hasMetrics := pos.validatorMetrics[validator]; hasMetrics && metrics.Status == StatusSlashed {
			slashedAmount = (amount * pos.slashingRate) / 100
			if slashedAmount > 0 {
				// Apply penalty by reducing total stake
				if slashedAmount > stake {
					slashedAmount = stake
				}
				pos.validators[validator] -= slashedAmount
				pos.totalStake -= slashedAmount
				metrics.SlashingPenalty += slashedAmount
			}
		}

		// Process requested withdrawal (adjusted for any slashing)
		remainingAmount := min(amount, stake-slashedAmount)

		pos.validators[validator] -= remainingAmount
		pos.totalStake -= remainingAmount

		// If validator's stake falls below minimum, remove them from validator set
		if pos.validators[validator] < pos.minStake {
			delete(pos.validators, validator)
			delete(pos.validatorMetrics, validator) // Clean up metrics

			// Remove from validatorsList
			for i, v := range pos.validatorsList {
				if v == validator {
					pos.validatorsList = slices.Delete(pos.validatorsList, i, i+1)
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
