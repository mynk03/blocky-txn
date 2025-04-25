package consensus

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// BenchmarkValidatorSelection benchmarks the performance of validator selection
func BenchmarkValidatorSelection(b *testing.B) {
	// Create a new PoS consensus instance
	pos := NewProofOfStake(1*time.Second, 100, 10)

	// Setup a varied set of validators with different stakes
	validatorCount := 100
	totalStake := uint64(0)

	for i := 0; i < validatorCount; i++ {
		// Create a unique address for each validator
		addr := common.BytesToAddress([]byte{byte(i), byte(i + 1), byte(i + 2)})

		// Assign a stake amount between 100 and 1000
		stake := uint64(100 + (i%10)*100)
		pos.Deposit(addr, stake)
		totalStake += stake
	}

	b.ResetTimer()

	// Benchmark the validator selection
	for i := 0; i < b.N; i++ {
		pos.SelectValidator()
	}
}

// BenchmarkDeposit benchmarks the performance of deposit operations
func BenchmarkDeposit(b *testing.B) {
	// Create a new PoS consensus instance using test helper
	pos := NewProofOfStake(1*time.Second, 100, 10)

	// Pre-generate addresses to avoid that overhead in benchmarking
	addresses := make([]common.Address, b.N)
	for i := 0; i < b.N; i++ {
		addresses[i] = common.BytesToAddress([]byte{byte(i), byte(i + 1), byte(i + 2)})
	}

	b.ResetTimer()

	// Benchmark deposit operations
	for i := 0; i < b.N; i++ {
		pos.Deposit(addresses[i], 200)
	}
}

// BenchmarkWithdraw benchmarks the performance of withdrawal operations
func BenchmarkWithdraw(b *testing.B) {
	// Create a new PoS consensus instance using test helper
	pos := NewProofOfStake(1*time.Second, 100, 10)

	// Pre-generate addresses and deposit funds
	addresses := make([]common.Address, b.N)
	for i := 0; i < b.N; i++ {
		addresses[i] = common.BytesToAddress([]byte{byte(i), byte(i + 1), byte(i + 2)})
		pos.Deposit(addresses[i], 200)
	}

	b.ResetTimer()

	// Benchmark withdrawal operations
	for i := 0; i < b.N; i++ {
		pos.Withdraw(addresses[i], 100)
	}
}

// BenchmarkGetValidatorSet benchmarks the performance of getting the validator set
func BenchmarkGetValidatorSet(b *testing.B) {
	// Create a new PoS consensus instance using test helper
	pos := NewProofOfStake(1*time.Second, 100, 10)

	// Setup a varied set of validators
	validatorCount := 100

	for i := 0; i < validatorCount; i++ {
		addr := common.BytesToAddress([]byte{byte(i), byte(i + 1), byte(i + 2)})
		pos.Deposit(addr, 200)
	}

	b.ResetTimer()

	// Benchmark getting the validator set
	for i := 0; i < b.N; i++ {
		pos.GetValidatorSet()
	}
}
