package consensus

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

// TestValidatorDistribution tests the validator selection distribution
// to ensure proper weighting based on stake
func TestValidatorDistribution(t *testing.T) {
	t.Parallel()

	// Create a new PoS consensus instance
	pos := CreateDefaultTestPoS(t)

	// Setup validators with different stake amounts
	// Validator1: 200 (20% of total)
	// Validator2: 300 (30% of total)
	// Validator3: 500 (50% of total)
	SetupValidators(pos, map[common.Address]uint64{
		TestValidators.Validator1: 200,
		TestValidators.Validator2: 300,
		TestValidators.Validator3: 500,
	})

	// Run multiple selections to get a distribution
	selections := map[common.Address]uint64{
		TestValidators.Validator1: 0,
		TestValidators.Validator2: 0,
		TestValidators.Validator3: 0,
	}

	// Make a large number of selections to get a statistically significant sample
	iterations := 1000
	for i := 0; i < iterations; i++ {
		selected := pos.SelectValidator()
		selections[selected]++
	}

	// Check that the distribution roughly matches the stake percentages
	// Allow for some statistical variance (±5%)
	assert.InDelta(t, 0.20, float64(selections[TestValidators.Validator1])/float64(iterations), 0.05,
		"Validator1 should be selected approximately 20% of the time")
	assert.InDelta(t, 0.30, float64(selections[TestValidators.Validator2])/float64(iterations), 0.05,
		"Validator2 should be selected approximately 30% of the time")
	assert.InDelta(t, 0.50, float64(selections[TestValidators.Validator3])/float64(iterations), 0.05,
		"Validator3 should be selected approximately 50% of the time")
}

// TestSelectionWithEmptySet tests validator selection with an empty validator set
func TestSelectionWithEmptySet(t *testing.T) {
	t.Parallel()

	// Create a new PoS consensus instance with no validators
	pos := CreateDefaultTestPoS(t)

	// SelectValidator should handle empty validator set gracefully
	selected := pos.SelectValidator()
	assert.Equal(t, common.Address{}, selected, "Should return empty address for empty validator set")
}

// TestSelectionWithSingleValidator tests validator selection with just one validator
func TestSelectionWithSingleValidator(t *testing.T) {
	t.Parallel()

	// Create a new PoS consensus instance
	pos := CreateDefaultTestPoS(t)

	// Setup a single validator
	SetupValidators(pos, map[common.Address]uint64{
		TestValidators.Validator1: 200,
	})

	// The single validator should always be selected
	for i := 0; i < 10; i++ {
		selected := pos.SelectValidator()
		assert.Equal(t, TestValidators.Validator1, selected, "The only validator should always be selected")
	}
}

// TestSelectionAfterRemoval tests validator selection after removing validators
func TestSelectionAfterRemoval(t *testing.T) {
	t.Parallel()

	// Create a new PoS consensus instance
	pos := CreateDefaultTestPoS(t)

	// Setup multiple validators
	SetupValidators(pos, map[common.Address]uint64{
		TestValidators.Validator1: 200,
		TestValidators.Validator2: 300,
		TestValidators.Validator3: 500,
	})

	// Remove one validator
	pos.Withdraw(TestValidators.Validator1, 200)

	// The removed validator should never be selected
	selections := map[common.Address]uint64{
		TestValidators.Validator1: 0,
		TestValidators.Validator2: 0,
		TestValidators.Validator3: 0,
	}

	// Use more iterations for more statistically reliable results
	iterations := 500
	for range iterations {
		selected := pos.SelectValidator()
		selections[selected]++
	}

	assert.Equal(t, uint64(0), selections[TestValidators.Validator1],
		"Removed validator should never be selected")

	// The remaining validators should be selected proportional to their stake
	// Validator2: 300 (37.5% of remaining total)
	// Validator3: 500 (62.5% of remaining total)
	// Use a generous tolerance for statistical variance (±15%)
	assert.InDelta(t, 0.375, float64(selections[TestValidators.Validator2])/float64(iterations), 0.15,
		"Validator2 should be selected approximately 37.5% of the time")
	assert.InDelta(t, 0.625, float64(selections[TestValidators.Validator3])/float64(iterations), 0.15,
		"Validator3 should be selected approximately 62.5% of the time")
}
