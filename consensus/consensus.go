// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// ConsensusAlgorithm interface defines the methods required for a consensus implementation
type ConsensusAlgorithm interface {
	// SelectValidator selects the next block validator.
	SelectValidator() common.Address

	// GetReward calculates the reward for the validator/miner.
	GetReward() uint64

	// Deposit deposits a validator's stake.
	Deposit(validator common.Address, amount uint64)

	// Withdraw withdraws a validator's stake.
	Withdraw(validator common.Address, amount uint64)

	// GetValidatorStake returns the stake of a validator.
	GetValidatorStake(validator common.Address) uint64

	// GetValidatorSet returns the current validator set.
	GetValidatorSet() []common.Address

	// GetSlotDuration returns the duration of a slot.
	GetSlotDuration() time.Duration

	// CalculateValidatorReward calculates the reward for a specific validator
	// based on their performance metrics and status.
	CalculateValidatorReward(validator common.Address) uint64

	// RecordBlockProduction records that a validator successfully produced a block
	RecordBlockProduction(validator common.Address)

	// RecordMissedValidation records that a validator missed their validation slot
	RecordMissedValidation(validator common.Address)

	// RecordDoubleSign records evidence of double signing (a serious violation)
	RecordDoubleSign(validator common.Address)

	// RecordInvalidTransaction records when a validator includes invalid transactions
	RecordInvalidTransaction(validator common.Address)

	// SlashValidator penalizes a validator by taking a percentage of their stake
	SlashValidator(validator common.Address, reason string)

	// ResetValidator resets a validator's metrics and status
	ResetValidator(validator common.Address)

	// GetValidatorStatus returns the current status of a validator
	GetValidatorStatus(validator common.Address) ValidatorStatus

	// GetValidatorMetrics returns the performance metrics for a validator
	GetValidatorMetrics(validator common.Address) *ValidationMetrics
}
