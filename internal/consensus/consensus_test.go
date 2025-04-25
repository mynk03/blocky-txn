package consensus

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

// ConsensusTestSuite is a test suite for consensus implementations
type ConsensusTestSuite struct {
	suite.Suite
	// Add common fields that might be used across multiple tests
}

// SetupSuite runs once before all tests in the suite
func (s *ConsensusTestSuite) SetupSuite() {
	// Setup code that should run once for the entire suite
}

// TearDownSuite runs once after all tests in the suite
func (s *ConsensusTestSuite) TearDownSuite() {
	// Cleanup code that should run once after all tests
}

// TestProofOfStake tests the Proof of Stake implementation
func (s *ConsensusTestSuite) TestProofOfStake() {
	// Test deposit functionality
	s.Run("Deposits", func() {
		// Create a fresh instance for this sub-test
		pos := CreateDefaultTestPoS(s.T())

		// Initially there should be no validators
		validators := pos.GetValidatorSet()
		s.Equal(0, len(validators), "Initial validator set should be empty")

		// Reference our test validators
		validator1 := TestValidators.Validator1
		validator2 := TestValidators.Validator2
		validator3 := TestValidators.Validator3

		// Validator 1 deposits 200
		pos.Deposit(validator1, 200)
		s.Equal(uint64(200), pos.GetValidatorStake(validator1), "Validator 1 should have 200 stake")
		s.Equal(1, len(pos.GetValidatorSet()), "Should have 1 validator after deposit")

		// Validator 2 deposits 300
		pos.Deposit(validator2, 300)
		s.Equal(uint64(300), pos.GetValidatorStake(validator2), "Validator 2 should have 300 stake")
		s.Equal(2, len(pos.GetValidatorSet()), "Should have 2 validators after second deposit")

		// Validator 3 deposits only 50 (less than minimum)
		pos.Deposit(validator3, 50)
		s.Equal(uint64(0), pos.GetValidatorStake(validator3), "Validator 3 should have 0 stake (below minimum)")
		s.Equal(2, len(pos.GetValidatorSet()), "Validator set should still have 2 validators")
	})

	// Test withdrawal functionality
	s.Run("Withdrawals", func() {
		// Create a fresh instance for this sub-test
		pos := CreateDefaultTestPoS(s.T())

		// Setup validators with initial stakes
		validator1 := TestValidators.Validator1
		validator2 := TestValidators.Validator2

		// Setup initial state: validator1 has 200 stake, validator2 has 300 stake
		SetupValidators(pos, map[common.Address]uint64{
			validator1: 299,
			validator2: 300,
		})

		s.Equal(uint64(299), pos.GetValidatorStake(validator1), "Validator 1 should initially have 299 stake")
		s.Equal(uint64(300), pos.GetValidatorStake(validator2), "Validator 2 should initially have 300 stake")
		s.Equal(2, len(pos.GetValidatorSet()), "Should initially have 2 validators")

		// Validator 1 withdraws 150
		pos.Withdraw(validator1, 150)
		s.Equal(uint64(149), pos.GetValidatorStake(validator1), "Validator 1 should have 250 stake after withdrawal")
		s.Equal(2, len(pos.GetValidatorSet()), "Validator set should still have 2 validators")

		// Validator 1 withdraws 50 more, falling below minimum
		pos.Withdraw(validator1, 50)
		s.Equal(uint64(0), pos.GetValidatorStake(validator1), "Validator 1 should have 0 stake after withdrawal")
		s.Equal(1, len(pos.GetValidatorSet()), "Validator set should have 1 validator after removal")
	})

	// Test other properties
	s.Run("Properties", func() {
		// Create a fresh instance for this sub-test
		pos := CreateDefaultTestPoS(s.T())

		// Check slot duration
		s.Equal(TestConfig.Default.SlotDuration, pos.GetSlotDuration(), "Slot duration should match default config")

		// Get reward
		s.Equal(TestConfig.Default.BaseReward, pos.GetReward(), "Reward should match default config")
	})

	// Test validator selection
	s.Run("Validator Selection", func() {
		// Create a fresh instance for this sub-test
		pos := CreateDefaultTestPoS(s.T())

		// Setup a single validator
		validator2 := TestValidators.Validator2
		SetupValidators(pos, map[common.Address]uint64{
			validator2: 300,
		})

		// Since we only have one validator, it should always be selected
		selected := pos.SelectValidator()
		s.Equal(validator2, selected, "Validator 2 should be selected")
	})
}

// TestProofOfStakeVariations tests different configurations of PoS
func (s *ConsensusTestSuite) TestProofOfStakeVariations() {
	// Test with different parameters
	s.Run("High Minimum Stake", func() {
		pos := CreateTestPoS(s.T(),
			TestConfig.HighStake.SlotDuration,
			TestConfig.HighStake.MinStake,
			TestConfig.HighStake.BaseReward)

		validator := TestValidators.Validator1

		// Deposit less than minimum
		pos.Deposit(validator, 400)
		s.Equal(uint64(0), pos.GetValidatorStake(validator), "Stake should be 0 (below minimum)")
		s.Equal(0, len(pos.GetValidatorSet()), "Validator set should be empty")

		// Deposit enough to meet minimum
		pos.Deposit(validator, 500)
		s.Equal(uint64(500), pos.GetValidatorStake(validator), "Stake should be 500")
		s.Equal(1, len(pos.GetValidatorSet()), "Validator set should have 1 validator")

		// Check other parameters
		s.Equal(TestConfig.HighStake.SlotDuration, pos.GetSlotDuration(), "Slot duration should match high stake config")
		s.Equal(TestConfig.HighStake.BaseReward, pos.GetReward(), "Reward should match high stake config")
	})
}

// TestProofOfStakeEdgeCases tests edge cases in the PoS implementation
func (s *ConsensusTestSuite) TestProofOfStakeEdgeCases() {
	s.Run("Empty Validator Set", func() {
		pos := CreateDefaultTestPoS(s.T())

		// SelectValidator should handle empty validator set gracefully
		selected := pos.SelectValidator()
		s.Equal(common.Address{}, selected, "Should return empty address for empty validator set")
	})

	s.Run("Withdrawing More Than Staked", func() {
		pos := CreateDefaultTestPoS(s.T())
		validator := TestValidators.Validator1

		// Setup validator with initial stake using helper
		SetupValidators(pos, map[common.Address]uint64{
			validator: 200,
		})

		s.Equal(uint64(200), pos.GetValidatorStake(validator), "Stake should be 200")

		// Try to withdraw 300 (more than staked)
		pos.Withdraw(validator, 300)
		s.Equal(uint64(0), pos.GetValidatorStake(validator), "Stake should be 0 after withdrawing all")
		s.Equal(0, len(pos.GetValidatorSet()), "Validator set should be empty")
	})

	s.Run("Multiple Validators Selection", func() {
		pos := CreateDefaultTestPoS(s.T())

		// Setup multiple validators with different stakes
		SetupValidators(pos, map[common.Address]uint64{
			TestValidators.Validator1: 200,
			TestValidators.Validator2: 300,
			TestValidators.Validator3: 500,
		})

		// Verify all validators are in the set
		s.Equal(3, len(pos.GetValidatorSet()), "Should have 3 validators")

		// Since selection is weighted random, we can't assert on specific outcome
		// But we can verify that a validator is selected and it's one of our validators
		selected := pos.SelectValidator()
		s.NotEqual(common.Address{}, selected, "Should select a validator")

		validValidators := map[common.Address]bool{
			TestValidators.Validator1: true,
			TestValidators.Validator2: true,
			TestValidators.Validator3: true,
		}

		s.True(validValidators[selected], "Selected validator should be one of the validators we set up")
	})
}

// Run the test suite
func TestConsensusSuite(t *testing.T) {
	suite.Run(t, new(ConsensusTestSuite))
}
