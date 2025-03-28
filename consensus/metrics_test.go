package consensus

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// TestGetValidatorMetrics tests the GetValidatorMetrics method
func TestGetValidatorMetrics(t *testing.T) {
	// Create a new PoS instance
	pos := CreateDefaultTestPoS(t)

	// Setup validators
	validator := TestValidators.Validator1
	pos.Deposit(validator, 200)

	// Test getting metrics for an existing validator
	metrics := pos.GetValidatorMetrics(validator)
	assert.NotNil(t, metrics, "Should return metrics for existing validator")
	assert.Equal(t, StatusActive, metrics.Status, "Validator should have active status")
	assert.Equal(t, uint64(0), metrics.BlocksProposed, "New validator should have 0 blocks proposed")
	assert.Equal(t, uint64(0), metrics.MissedValidations, "New validator should have 0 missed validations")

	// Record some activity
	pos.RecordBlockProduction(validator)
	pos.RecordMissedValidation(validator)

	// Get updated metrics
	updatedMetrics := pos.GetValidatorMetrics(validator)
	assert.Equal(t, uint64(1), updatedMetrics.BlocksProposed, "Should have 1 block proposed")
	assert.Equal(t, uint64(1), updatedMetrics.BlocksValidated, "Should have 1 block validated")
	assert.Equal(t, uint64(1), updatedMetrics.MissedValidations, "Should have 1 missed validation")

	// Test getting metrics for non-existent validator
	nonExistentValidator := common.HexToAddress("0x9999999999999999999999999999999999999999")
	noMetrics := pos.GetValidatorMetrics(nonExistentValidator)
	assert.Nil(t, noMetrics, "Should return nil for non-existent validator")

	// Test metrics immutability (changing the returned metrics shouldn't affect the stored ones)
	metrics.BlocksProposed = 999
	latestMetrics := pos.GetValidatorMetrics(validator)
	assert.Equal(t, uint64(1), latestMetrics.BlocksProposed, "Original metrics should remain unchanged")
}

// TestRecordBlockProductionEdgeCases tests edge cases for block production recording
func TestRecordBlockProductionEdgeCases(t *testing.T) {
	// Create a new PoS instance
	pos := CreateDefaultTestPoS(t)

	// Test recording block production for non-existent validator
	// This should create metrics for this validator even though they aren't staked
	nonExistentValidator := common.HexToAddress("0x8888888888888888888888888888888888888888")
	pos.RecordBlockProduction(nonExistentValidator)

	// Verify metrics were created
	metrics := pos.GetValidatorMetrics(nonExistentValidator)
	assert.NotNil(t, metrics, "Metrics should be created for new validator")
	assert.Equal(t, uint64(1), metrics.BlocksProposed, "Should record one block")
	assert.Equal(t, uint64(1), metrics.BlocksValidated, "Should record one validation")

	// Record multiple blocks and check metrics are properly incremented
	for range 5 {
		pos.RecordBlockProduction(nonExistentValidator)
	}

	updatedMetrics := pos.GetValidatorMetrics(nonExistentValidator)
	assert.Equal(t, uint64(6), updatedMetrics.BlocksProposed, "Should have recorded 6 blocks total")
}

// TestDepositEdgeCases tests edge cases for deposits
func TestDepositEdgeCases(t *testing.T) {
	// Create a new PoS instance
	pos := CreateDefaultTestPoS(t)
	validator := TestValidators.Validator1

	// Test depositing less than minimum stake (should not add to validator set)
	belowMinStake := pos.minStake - 1
	pos.Deposit(validator, belowMinStake)

	// Verify validator wasn't added
	validatorSet := pos.GetValidatorSet()
	assert.Equal(t, 0, len(validatorSet), "Validator set should be empty")
	assert.Equal(t, 0, pos.GetValidatorStake(validator), "Validator should have 0 stake")

	// Now deposit enough to meet minimum stake
	pos.Deposit(validator, pos.minStake)
	assert.Equal(t, pos.minStake, pos.GetValidatorStake(validator), "Validator should have minimum stake")
	assert.Equal(t, 1, len(pos.GetValidatorSet()), "Validator set should have 1 validator")

	// Additional deposits should increase stake
	additionalStake := 50
	pos.Deposit(validator, additionalStake)
	assert.Equal(t, pos.minStake+additionalStake, pos.GetValidatorStake(validator), "Stake should increase")
}

// TestSlashValidator tests slashing a validator
func TestSlashValidator(t *testing.T) {
	// Create a new PoS instance
	pos := CreateDefaultTestPoS(t)

	// Test slashing a non-existent validator (should not error)
	nonExistentValidator := common.HexToAddress("0x7777777777777777777777777777777777777777")
	pos.SlashValidator(nonExistentValidator, "Test reason")
	assert.Equal(t, StatusActive, pos.GetValidatorStatus(nonExistentValidator), "Non-existent validator should be treated as active")

	// Setup a real validator
	validatorToSlash := TestValidators.Validator2
	pos.Deposit(validatorToSlash, 300)

	// Initial status should be active
	assert.Equal(t, StatusActive, pos.GetValidatorStatus(validatorToSlash), "Initial status should be active")

	// Slash the validator
	pos.SlashValidator(validatorToSlash, "Test slash reason")
	assert.Equal(t, StatusSlashed, pos.GetValidatorStatus(validatorToSlash), "Validator should be slashed")
}

// TestWithdrawSlashedValidator tests withdrawing from a slashed validator
func TestWithdrawSlashedValidator(t *testing.T) {
	// Create a new PoS instance
	pos := CreateDefaultTestPoS(t)

	// Setup a validator with stake
	validator := TestValidators.Validator1
	initialStake := 500
	pos.Deposit(validator, initialStake)

	// Slash the validator
	pos.SlashValidator(validator, "Test slash reason")

	// Verify status is slashed
	assert.Equal(t, StatusSlashed, pos.GetValidatorStatus(validator), "Validator should be slashed")

	// Withdraw part of the stake
	withdrawAmount := 200
	pos.Withdraw(validator, withdrawAmount)

	// Calculate expected slashing penalty
	slashingPenalty := (withdrawAmount * pos.slashingRate) / 100

	// Verify remaining stake after slashing and withdrawal
	expectedRemainingStake := initialStake - withdrawAmount - slashingPenalty
	assert.Equal(t, expectedRemainingStake, pos.GetValidatorStake(validator), "Remaining stake should account for slashing")

	// Withdraw all remaining stake
	pos.Withdraw(validator, expectedRemainingStake)

	// Verify validator is removed from set
	assert.Equal(t, 0, pos.GetValidatorStake(validator), "Validator should have 0 stake")
	assert.Equal(t, 0, len(pos.GetValidatorSet()), "Validator set should be empty")
}

// TestRecordInvalidTransactionEdgeCases tests edge cases for invalid transaction recording
func TestRecordInvalidTransactionEdgeCases(t *testing.T) {
	// Create a new PoS instance
	pos := CreateDefaultTestPoS(t)

	// Test recording invalid transaction for non-existent validator (should not error)
	nonExistentValidator := common.HexToAddress("0x6666666666666666666666666666666666666666")
	pos.RecordInvalidTransaction(nonExistentValidator)

	// Set up a real validator
	validator := TestValidators.Validator1
	pos.Deposit(validator, 200)

	// Get initial status value
	assert.Equal(t, StatusActive, pos.GetValidatorStatus(validator), "Initial status should be active")

	// Record just below the probation threshold
	for range int(pos.probationThreshold)-1 {
		pos.RecordInvalidTransaction(validator)
	}

	// Verify status is still active
	metrics := pos.GetValidatorMetrics(validator)
	assert.Equal(t, StatusActive, metrics.Status, "Status should remain active below threshold")

	// Record one more to hit the threshold
	pos.RecordInvalidTransaction(validator)

	// Verify status is now probation
	metrics = pos.GetValidatorMetrics(validator)
	assert.Equal(t, StatusProbation, metrics.Status, "Status should change to probation at threshold")

	// Record more to hit slashing threshold
	for range int(pos.slashThreshold) {
		pos.RecordInvalidTransaction(validator)
	}

	// Verify status is slashed
	metrics = pos.GetValidatorMetrics(validator)
	assert.Equal(t, StatusSlashed, metrics.Status, "Status should change to slashed")
}

// TestMetricsSuite comprehensive test suite for validator metrics
type MetricsSuite struct {
	suite.Suite
	pos        *ProofOfStake
	validators map[string]common.Address
}

// SetupTest runs before each test in the suite
func (s *MetricsSuite) SetupTest() {
	// Create a test PoS instance with validators in different states
	s.pos, s.validators = CreateTestValidatorSet(s.T())

	// Configure thresholds to ensure expected test behavior
	ConfigureThresholds(
		s.pos,
		5,  // probationThreshold
		15, // slashThreshold
		20, // slashingRate
	)
}

// TestGetMetrics tests getting validator metrics
func (s *MetricsSuite) TestGetMetrics() {
	// Test getting metrics for an existing validator
	metrics := s.pos.GetValidatorMetrics(s.validators["active"])
	s.NotNil(metrics, "Should return metrics for existing validator")
	s.Equal(StatusActive, metrics.Status, "Validator should have active status")
	s.Equal(uint64(0), metrics.BlocksProposed, "New validator should have 0 blocks proposed")
	s.Equal(uint64(0), metrics.MissedValidations, "New validator should have 0 missed validations")

	// Test getting metrics for non-existent validator
	nonExistentValidator := common.HexToAddress("0x9999999999999999999999999999999999999999")
	noMetrics := s.pos.GetValidatorMetrics(nonExistentValidator)
	s.Nil(noMetrics, "Should return nil for non-existent validator")

	// Test metrics immutability (changing the returned metrics shouldn't affect the stored ones)
	metrics.BlocksProposed = 999
	latestMetrics := s.pos.GetValidatorMetrics(s.validators["active"])
	s.Equal(uint64(0), latestMetrics.BlocksProposed, "Original metrics should remain unchanged")
}

// TestRecordBlockProduction tests recording block production
func (s *MetricsSuite) TestRecordBlockProduction() {
	// Record block production
	s.pos.RecordBlockProduction(s.validators["active"])
	metrics := s.pos.GetValidatorMetrics(s.validators["active"])
	s.Equal(uint64(1), metrics.BlocksProposed, "Should record one block proposed")
	s.Equal(uint64(1), metrics.BlocksValidated, "Should record one block validated")

	// Test recording block for non-existent validator (should create metrics)
	nonExistentValidator := common.HexToAddress("0x8888888888888888888888888888888888888888")
	s.pos.RecordBlockProduction(nonExistentValidator)
	newMetrics := s.pos.GetValidatorMetrics(nonExistentValidator)
	s.NotNil(newMetrics, "Should create metrics for new validator")
	s.Equal(uint64(1), newMetrics.BlocksProposed, "Should record one block for new validator")
}

// TestRewardCalculation tests the reward calculation logic
func (s *MetricsSuite) TestRewardCalculation() {
	// Get initial rewards
	activeReward := s.pos.CalculateValidatorReward(s.validators["active"])
	probationReward := s.pos.CalculateValidatorReward(s.validators["probation"])
	slashedReward := s.pos.CalculateValidatorReward(s.validators["slashed"])

	// Verify rewards by status
	s.Greater(activeReward, 0, "Active validator should receive positive reward")
	s.Less(probationReward, activeReward, "Probation reward should be less than active reward")
	s.Equal(0, slashedReward, "Slashed validator should receive no reward")

	// Test consecutive block bonus
	// Record several blocks for the active validator
	for range 5 {
		s.pos.RecordBlockProduction(s.validators["active"])
	}

	newActiveReward := s.pos.CalculateValidatorReward(s.validators["active"])
	s.GreaterOrEqual(newActiveReward, activeReward, "Reward should increase or remain the same after consecutive block production")

	// Test non-existent validator
	nonExistentValidator := common.HexToAddress("0x7777777777777777777777777777777777777777")
	s.Equal(0, s.pos.CalculateValidatorReward(nonExistentValidator), "Non-existent validator should get 0 reward")
}

// TestStatusTransitions tests validator status transitions
func (s *MetricsSuite) TestStatusTransitions() {
	// Test status escalation (Active -> Probation -> Slashed)
	validator := s.validators["active"]

	// Initially active
	s.Equal(StatusActive, s.pos.GetValidatorStatus(validator), "Validator should start as active")

	// Ensure clear threshold values with well-defined progression
	s.pos.probationThreshold = 5
	s.pos.slashThreshold = 15

	// 1. Set missed validations to probation threshold and trigger transition
	s.pos.validatorMetrics[validator].MissedValidations = s.pos.probationThreshold - 1
	s.pos.RecordMissedValidation(validator)

	// Should change to probation
	s.Equal(StatusProbation, s.pos.GetValidatorStatus(validator), "Status should change to probation")

	// 2. Reset validator status
	s.pos.ResetValidator(validator)
	s.Equal(StatusActive, s.pos.GetValidatorStatus(validator), "Status should reset to active")

	// 3. Test slashing
	s.pos.SlashValidator(validator, "Test slashing")
	s.Equal(StatusSlashed, s.pos.GetValidatorStatus(validator), "Status should be slashed")
}

// TestMissedValidations tests missed validation recording and penalties
func (s *MetricsSuite) TestMissedValidations() {
	// Create a new validator for this test
	validator := common.HexToAddress("0x5555555555555555555555555555555555555555")
	s.pos.Deposit(validator, 200)

	// Make sure validator starts with clean metrics
	s.pos.validatorMetrics[validator].MissedValidations = 0
	s.pos.validatorMetrics[validator].Status = StatusActive

	// Ensure clear threshold values with well-defined progression
	s.pos.probationThreshold = 5
	s.pos.slashThreshold = 15

	// Verify initial status
	initialMetrics := s.pos.GetValidatorMetrics(validator)
	s.Equal(StatusActive, initialMetrics.Status, "Validator should start as active")
	s.Equal(uint64(0), initialMetrics.MissedValidations, "Should start with 0 missed validations")

	// Test progression to probation
	for range int(s.pos.probationThreshold) {
		s.pos.RecordMissedValidation(validator)
	}
	s.Equal(StatusProbation, s.pos.GetValidatorStatus(validator),
		"Status should change to probation after probation threshold")

	// Test progression to slashed
	s.pos.validatorMetrics[validator].MissedValidations = s.pos.slashThreshold - 1
	s.pos.validatorMetrics[validator].Status = StatusProbation // Ensure we start from probation status
	s.pos.RecordMissedValidation(validator)
	s.Equal(StatusSlashed, s.pos.GetValidatorStatus(validator),
		"Status should change to slashed after slash threshold")

	// Test for non-existent validator (should not panic)
	nonExistentValidator := common.HexToAddress("0x6666666666666666666666666666666666666666")
	s.pos.RecordMissedValidation(nonExistentValidator)
}

// TestDoubleSign tests double signing recording and penalties
func (s *MetricsSuite) TestDoubleSign() {
	// Create a new validator for this test
	validator := common.HexToAddress("0x5555555555555555555555555555555555555555")
	s.pos.Deposit(validator, 200)

	// Ensure validator starts with clean metrics
	s.pos.validatorMetrics[validator].Status = StatusActive
	s.pos.validatorMetrics[validator].DoubleSignings = 0

	// Record first double signing
	s.pos.RecordDoubleSign(validator)
	metrics := s.pos.GetValidatorMetrics(validator)
	s.Equal(uint64(1), metrics.DoubleSignings, "Should record double signing")
	s.Equal(StatusProbation, metrics.Status, "First double signing should put validator on probation")

	// Reset for second double signing
	metrics.Status = StatusActive

	// Record second double signing
	s.pos.RecordDoubleSign(validator)
	metrics = s.pos.GetValidatorMetrics(validator)
	s.Equal(uint64(2), metrics.DoubleSignings, "Should record second double signing")
	s.Equal(StatusSlashed, metrics.Status, "Second double signing should slash validator")

	// Test double signing for non-existent validator (should not panic)
	nonExistentValidator := common.HexToAddress("0x3333333333333333333333333333333333333334")
	s.pos.RecordDoubleSign(nonExistentValidator)
}

// TestMetricsReset tests the reset of validator metrics
func (s *MetricsSuite) TestMetricsReset() {
	validator := s.validators["probation"]

	// Get initial metrics
	initialMetrics := s.pos.GetValidatorMetrics(validator)
	s.Equal(StatusProbation, initialMetrics.Status, "Validator should start in probation")

	// Record additional negative events
	s.pos.RecordMissedValidation(validator)
	s.pos.RecordInvalidTransaction(validator)

	// Record initial block count
	initialBlocks := s.pos.GetValidatorMetrics(validator).BlocksProposed

	// Reset validator
	s.pos.ResetValidator(validator)

	// Check metrics after reset
	resetMetrics := s.pos.GetValidatorMetrics(validator)
	s.Equal(StatusActive, resetMetrics.Status, "Status should be reset to active")
	s.Equal(uint64(0), resetMetrics.MissedValidations, "Missed validations should be reset")
	s.Equal(uint64(0), resetMetrics.InvalidTransactions, "Invalid transactions should be reset")

	// Check that blocks proposed are preserved
	s.Equal(initialBlocks, resetMetrics.BlocksProposed, "Blocks proposed should be preserved")

	// Test resetting a non-existent validator (should not panic)
	nonExistentValidator := common.HexToAddress("0x1111111111111111111111111111111111111112")
	s.pos.ResetValidator(nonExistentValidator)
}

// Run the test suite
func TestMetricsSuite(t *testing.T) {
	suite.Run(t, new(MetricsSuite))
}
