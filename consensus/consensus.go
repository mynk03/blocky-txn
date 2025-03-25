	package consensus

	import (
		"time"

		"github.com/ethereum/go-ethereum/common"
	)

	type ConsensusAlgorithm interface {
		// SelectValidator selects the next block validator.
		SelectValidator() common.Address

		// GetReward calculates the reward for the validator/miner.
		GetReward() int

		// Deposit deposits a validator's stake.
		Deposit(validator common.Address, amount int)

		// Withdraw withdraws a validator's stake.
		Withdraw(validator common.Address, amount int)

		// GetValidatorStake returns the stake of a validator.
		GetValidatorStake(validator common.Address) int

		// GetValidatorSet returns the current validator set.
		GetValidatorSet() []common.Address

		// GetSlotDuration returns the duration of a slot.
		GetSlotDuration() time.Duration
	}
