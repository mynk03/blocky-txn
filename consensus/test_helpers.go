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
		SlotDuration time.Duration
		MinStake     int
		BaseReward   int
	}
	HighStake struct {
		SlotDuration time.Duration
		MinStake     int
		BaseReward   int
	}
}{
	Default: struct {
		SlotDuration time.Duration
		MinStake     int
		BaseReward   int
	}{
		SlotDuration: 5 * time.Second,
		MinStake:     100,
		BaseReward:   10,
	},
	HighStake: struct {
		SlotDuration time.Duration
		MinStake     int
		BaseReward   int
	}{
		SlotDuration: 10 * time.Second,
		MinStake:     500,
		BaseReward:   20,
	},
}

// CreateTestPoS creates a new ProofOfStake instance for testing
func CreateTestPoS(t *testing.T, slotDuration time.Duration, minStake, baseReward int) *ProofOfStake {
	t.Helper()
	return NewProofOfStake(slotDuration, minStake, baseReward)
}

// CreateDefaultTestPoS creates a new ProofOfStake with default settings
func CreateDefaultTestPoS(t *testing.T) *ProofOfStake {
	t.Helper()
	return CreateTestPoS(t, TestConfig.Default.SlotDuration, TestConfig.Default.MinStake, TestConfig.Default.BaseReward)
}

// SetupValidators sets up the specified validators with their respective stakes
func SetupValidators(pos *ProofOfStake, validatorStakes map[common.Address]int) {
	for validator, stake := range validatorStakes {
		pos.Deposit(validator, stake)
	}
}
