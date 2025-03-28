package consensus

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// TestValidators provides commonly used validator addresses for tests
var TestValidators = struct {
	Validator1 common.Address
	Validator2 common.Address
	Validator3 common.Address
}{
	Validator1: common.HexToAddress("0x1111111111111111111111111111111111111111"),
	Validator2: common.HexToAddress("0x2222222222222222222222222222222222222222"),
	Validator3: common.HexToAddress("0x3333333333333333333333333333333333333333"),
}

// TestConfig provides different test configurations for consensus tests
var TestConfig = struct {
	Default struct {
		SlotDuration       time.Duration
		MinStake           uint64
		BaseReward         uint64
		ProbationThreshold uint64
		SlashThreshold     uint64
		SlashingRate       uint8
	}
	HighStake struct {
		SlotDuration       time.Duration
		MinStake           uint64
		BaseReward         uint64
		ProbationThreshold uint64
		SlashThreshold     uint64
		SlashingRate       uint8
	}
}{
	Default: struct {
		SlotDuration       time.Duration
		MinStake           uint64
		BaseReward         uint64
		ProbationThreshold uint64
		SlashThreshold     uint64
		SlashingRate       uint8
	}{
		SlotDuration:       5 * time.Second,
		MinStake:           100,
		BaseReward:         10,
		ProbationThreshold: 5,
		SlashThreshold:     15,
		SlashingRate:       20,
	},
	HighStake: struct {
		SlotDuration       time.Duration
		MinStake           uint64
		BaseReward         uint64
		ProbationThreshold uint64
		SlashThreshold     uint64
		SlashingRate       uint8
	}{
		SlotDuration:       10 * time.Second,
		MinStake:           500,
		BaseReward:         20,
		ProbationThreshold: 5,
		SlashThreshold:     15,
		SlashingRate:       20,
	},
}

// CreateTestPoS creates a new ProofOfStake instance for testing
func CreateTestPoS(t *testing.T, slotDuration time.Duration, minStake, baseReward uint64) *ProofOfStake {
	t.Helper()
	pos := NewProofOfStake(slotDuration, minStake, baseReward)

	// Set default threshold values for test consistency
	pos.probationThreshold = TestConfig.Default.ProbationThreshold
	pos.slashThreshold = TestConfig.Default.SlashThreshold
	pos.slashingRate = TestConfig.Default.SlashingRate

	return pos
}

// CreateDefaultTestPoS creates a new ProofOfStake with default settings
func CreateDefaultTestPoS(t *testing.T) *ProofOfStake {
	t.Helper()
	return CreateTestPoS(t, TestConfig.Default.SlotDuration, TestConfig.Default.MinStake, TestConfig.Default.BaseReward)
}

// SetupValidators sets up the specified validators with their respective stakes
func SetupValidators(pos *ProofOfStake, validatorStakes map[common.Address]uint64) {
	for validator, stake := range validatorStakes {
		pos.Deposit(validator, stake)
	}
}

// SetupValidatorWithMetrics sets up a validator with the specified stake and metrics
func SetupValidatorWithMetrics(pos *ProofOfStake, validator common.Address, stake uint64, status ValidatorStatus, missedValidations uint64, doubleSignings uint64, invalidTxs uint64) {
	// Add the validator to the set
	pos.Deposit(validator, stake)

	// Set up metrics if the validator exists
	if pos.GetValidatorStake(validator) > 0 {
		metrics := pos.validatorMetrics[validator]
		metrics.Status = status
		metrics.MissedValidations = missedValidations
		metrics.DoubleSignings = doubleSignings
		metrics.InvalidTransactions = invalidTxs
	}
}

// ConfigureThresholds configures the thresholds for a ProofOfStake instance
func ConfigureThresholds(pos *ProofOfStake, probationThreshold, slashThreshold uint64, slashingRate uint8) {
	pos.probationThreshold = probationThreshold
	pos.slashThreshold = slashThreshold
	pos.slashingRate = slashingRate
}

// CreateTestValidatorSet creates a set of validators with different statuses for testing
func CreateTestValidatorSet(t *testing.T) (*ProofOfStake, map[string]common.Address) {
	pos := CreateDefaultTestPoS(t)

	// Create validators with different statuses
	active := TestValidators.Validator1
	probation := TestValidators.Validator2
	slashed := common.HexToAddress("0x4444444444444444444444444444444444444444")

	// Setup validators with different stakes and metrics
	SetupValidatorWithMetrics(pos, active, 200, StatusActive, 0, 0, 0)
	SetupValidatorWithMetrics(pos, probation, 300, StatusProbation, 6, 0, 0)
	SetupValidatorWithMetrics(pos, slashed, 500, StatusSlashed, 0, 2, 0)

	// Return a map for easy access
	validators := map[string]common.Address{
		"active":    active,
		"probation": probation,
		"slashed":   slashed,
	}

	return pos, validators
}
