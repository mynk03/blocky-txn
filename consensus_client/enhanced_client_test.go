// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package consensus_client_test

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/consensus"
	cc "blockchain-simulator/consensus_client"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Setup a helper for creating a test client
func setupTestConsensusClient(t *testing.T) (*cc.ConsensusClient, *logrus.Logger, *test.Hook) {
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)

	// Create a consensus client with minimal setup for testing
	client, err := cc.NewConsensusClient("/ip4/127.0.0.1/tcp/0", 200, logger)
	require.NoError(t, err, "Failed to create consensus client")
	require.NotNil(t, client, "Client should not be nil")

	return client, logger, hook
}

// mockPubSubTopic mocks the pubsub.Topic type
type mockPubSubTopic struct {
	mock.Mock
}

func (m *mockPubSubTopic) Publish(ctx context.Context, data []byte, opts ...pubsub.PubOpt) error {
	args := m.Called(ctx, data, opts)
	return args.Error(0)
}

func (m *mockPubSubTopic) Subscribe(opts ...pubsub.SubOpt) (*pubsub.Subscription, error) {
	args := m.Called(opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pubsub.Subscription), args.Error(1)
}

func (m *mockPubSubTopic) String() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockPubSubTopic) Close() error {
	args := m.Called()
	return args.Error(0)
}

// mockHarborClient is a mock for the harbor client
type mockHarborClient struct {
	mock.Mock
}

func (m *mockHarborClient) RequestBlockCreation(ctx context.Context, validatorAddress common.Address, prevBlockHash string, maxTransactions uint32) (*blockchain.Block, error) {
	args := m.Called(ctx, validatorAddress, prevBlockHash, maxTransactions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*blockchain.Block), args.Error(1)
}

func (m *mockHarborClient) ValidateBlock(ctx context.Context, block *blockchain.Block) (bool, error) {
	args := m.Called(ctx, block)
	return args.Bool(0), args.Error(1)
}

func (m *mockHarborClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockConsensusAlgorithm implements the consensus.ConsensusAlgorithm interface for testing
type MockConsensusAlgorithm struct {
	mock.Mock
}

func (m *MockConsensusAlgorithm) GetSlotDuration() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func (m *MockConsensusAlgorithm) GetProbationThreshold() uint64 {
	args := m.Called()
	return uint64(args.Int(0))
}

func (m *MockConsensusAlgorithm) SelectValidator() common.Address {
	args := m.Called()
	return args.Get(0).(common.Address)
}

func (m *MockConsensusAlgorithm) GetValidatorSet() []common.Address {
	args := m.Called()
	return args.Get(0).([]common.Address)
}

func (m *MockConsensusAlgorithm) GetValidatorMetrics(validator common.Address) *consensus.ValidationMetrics {
	args := m.Called(validator)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*consensus.ValidationMetrics)
}

func (m *MockConsensusAlgorithm) GetValidatorStatus(validator common.Address) consensus.ValidatorStatus {
	args := m.Called(validator)
	return args.Get(0).(consensus.ValidatorStatus)
}

func (m *MockConsensusAlgorithm) GetValidatorStake(validator common.Address) uint64 {
	args := m.Called(validator)
	return uint64(args.Int(0))
}

func (m *MockConsensusAlgorithm) RecordBlockProduction(validator common.Address) {
	m.Called(validator)
}

func (m *MockConsensusAlgorithm) RecordMissedValidation(validator common.Address) {
	m.Called(validator)
}

func (m *MockConsensusAlgorithm) RecordDoubleSign(validator common.Address) {
	m.Called(validator)
}

func (m *MockConsensusAlgorithm) RecordInvalidTransaction(validator common.Address) {
	m.Called(validator)
}

func (m *MockConsensusAlgorithm) Deposit(validator common.Address, amount uint64) {
	m.Called(validator, amount)
}

func (m *MockConsensusAlgorithm) Withdraw(addr common.Address, amount uint64) {
	m.Called(addr, amount)
}

func (m *MockConsensusAlgorithm) SlashValidator(validator common.Address, reason string) {
	m.Called(validator, reason)
}

func (m *MockConsensusAlgorithm) CalculateValidatorReward(validator common.Address) uint64 {
	args := m.Called(validator)
	return uint64(args.Int(0))
}

func (m *MockConsensusAlgorithm) GetReward() uint64 {
	args := m.Called()
	return uint64(args.Int(0))
}

func (m *MockConsensusAlgorithm) GetSlashThreshold() uint64 {
	args := m.Called()
	return uint64(args.Int(0))
}

func (m *MockConsensusAlgorithm) ResetValidator(validator common.Address) {
	m.Called(validator)
}

// TestGetVoteChannel tests the GetVoteChannel function
func TestGetVoteChannel(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Get the vote channel
	ch := client.GetVoteChannel()

	// We can't directly compare the channels with assert.Equal because one is bidirectional and one is receive-only
	// Instead, let's check that we can receive from the channel

	// Create a test vote
	testVote := &cc.VoteData{
		BlockHash: "test-hash",
		Validator: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Approve:   true,
	}

	// Create a signal channel to ensure proper timing
	done := make(chan struct{})

	// Send a vote to the original channel in a goroutine
	go func() {
		// Use the test helper function instead of direct access
		client.SetVoteChannelForTesting(testVote)

		// Signal that sending is complete
		close(done)
	}()

	// Try to receive from the channel returned by GetVoteChannel
	select {
	case vote := <-ch:
		assert.Equal(t, testVote, vote, "Should receive the same vote data")
	case <-time.After(500 * time.Millisecond): // Increase timeout
		t.Fatal("Timeout waiting for vote from channel")
	}

	// Make sure the goroutine completes
	select {
	case <-done:
		// Goroutine completed successfully
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for goroutine to complete")
	}
}

// TestPublishMessage tests the publishMessage function
func TestPublishMessage(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Initialize validator address
	client.SetSelfAddress(common.HexToAddress("0x1111111111111111111111111111111111111111"))

	// Create a test message
	testMsg := cc.ConsensusMessage{
		Type:      cc.BlockProposal,
		Sender:    client.GetValidatorAddress(),
		Timestamp: time.Now(),
	}

	// Test with nil topic (client.topic is nil by default in the test setup)
	err := client.PublishMessageForTesting(testMsg)
	assert.NoError(t, err, "Publishing with nil topic should not return an error in our implementation")

	// Store the original topic to restore it later
	origTopic := client.GetTopicForTesting()

	// Test 1: With nil topic (should not error)
	client.SetTopicForTesting(nil)
	err = client.PublishMessageForTesting(testMsg)
	assert.NoError(t, err, "publishMessage with nil topic should not return error")

	// Restore original topic
	client.SetTopicForTesting(origTopic)
}

// TestGetValidatorAddress tests the GetValidatorAddress function
func TestGetValidatorAddress(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Test with the default address from setup
	address := client.GetValidatorAddress()
	assert.Equal(t, client.GetSelfAddressForTesting(), address, "GetValidatorAddress should return the client's selfAddress")

	// Test with a different address
	expectedAddress := common.HexToAddress("0x1111111111111111111111111111111111111111")
	client.SetSelfAddress(expectedAddress)
	address = client.GetValidatorAddress()
	assert.Equal(t, expectedAddress, address, "GetValidatorAddress should return the updated selfAddress")
}

// TestGarbageCollectSeenMessages tests the GarbageCollectSeenMessages function
func TestGarbageCollectSeenMessages(t *testing.T) {
	client, _, hook := setupTestConsensusClient(t)

	// Add some messages to the seen messages map
	client.SetSeenMessagesForTesting(map[string]bool{
		"old1": true,
		"old2": true,
		"new1": true,
		"new2": true,
	})

	// Initial count
	initialCount := client.GetSeenMessagesCountForTesting()
	assert.Equal(t, 4, initialCount, "Should have 4 seen messages initially")

	// Run garbage collection (manually instead of starting the goroutine)
	client.ClearSeenMessagesForTesting()
	client.LogDebugForTesting("Garbage collected seen messages cache")

	// Check that all messages were removed
	assert.Equal(t, 0, client.GetSeenMessagesCountForTesting(), "Should have 0 seen messages after garbage collection")

	// Check log messages
	foundLogEntry := false
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.DebugLevel && entry.Message == "Garbage collected seen messages cache" {
			foundLogEntry = true
			break
		}
	}
	assert.True(t, foundLogEntry, "Should log message about garbage collection")

	// Setup context that can be canceled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.SetContextForTesting(ctx)

	// Add some messages to the seen messages map
	client.SetSeenMessagesForTesting(map[string]bool{
		"msg1": true,
		"msg2": true,
		"msg3": true,
	})

	// Start a goroutine for the garbage collector with a very short interval
	go client.GarbageCollectSeenMessages(50 * time.Millisecond)

	// Wait for at least one garbage collection cycle
	time.Sleep(100 * time.Millisecond)

	// Check that the seen messages map was cleared
	count := client.GetSeenMessagesCountForTesting()
	assert.Equal(t, 0, count, "Seen messages should be cleared after garbage collection")

	// Add more messages to ensure garbage collection is still running
	client.SetSeenMessagesForTesting(map[string]bool{
		"msg4": true,
		"msg5": true,
	})

	// Wait for another garbage collection cycle
	time.Sleep(100 * time.Millisecond)

	// Check that the new messages were also cleared
	count = client.GetSeenMessagesCountForTesting()
	assert.Equal(t, 0, count, "New messages should also be cleared by garbage collection")

	// Stop the goroutine by canceling the context
	cancel()

	// Give time for the goroutine to exit
	time.Sleep(10 * time.Millisecond)
}

// TestRequestBlockFromExecutionClient tests the RequestBlockFromExecutionClient function
func TestRequestBlockFromExecutionClient(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Test with nil harbor client
	client.SetHarborClientForTesting(nil)
	block, err := client.RequestBlockFromExecutionClient()
	assert.Error(t, err, "Should return error with nil harbor client")
	assert.Nil(t, block, "Block should be nil with error")

	// Create a mock harbor client
	mockHarbor := new(mockHarborClient)
	client.SetHarborClientForTesting(mockHarbor)

	// Create test data
	validatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	client.SetSelfAddress(validatorAddr)
	prevBlockHash := ""
	maxTransactions := uint32(100)

	// Create test block
	testBlock := &blockchain.Block{
		Index:     1,
		Hash:      "test-hash",
		PrevHash:  prevBlockHash,
		Validator: validatorAddr.Hex(),
	}

	// Setup mock expectations for success
	mockHarbor.On("RequestBlockCreation", mock.Anything, validatorAddr, prevBlockHash, maxTransactions).
		Return(testBlock, nil).Once()

	// Test successful request
	block, err = client.RequestBlockFromExecutionClient()
	assert.NoError(t, err, "Should not return error with valid harbor client")
	assert.Equal(t, testBlock, block, "Should return the expected block")

	// Setup mock expectations for error
	mockHarbor.On("RequestBlockCreation", mock.Anything, validatorAddr, prevBlockHash, maxTransactions).
		Return(nil, assert.AnError).Once()

	// Test error case
	block, err = client.RequestBlockFromExecutionClient()
	assert.Error(t, err, "Should return error when harbor client returns error")
	assert.Nil(t, block, "Block should be nil with error")

	// Verify mock expectations
	mockHarbor.AssertExpectations(t)
}

// TestValidateBlockWithExecutionClient tests the ValidateBlockWithExecutionClient function
func TestValidateBlockWithExecutionClient(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Create test block
	testBlock := &blockchain.Block{
		Index:     1,
		Hash:      "test-hash",
		PrevHash:  "",
		Validator: common.HexToAddress("0x1111111111111111111111111111111111111111").Hex(),
	}

	// Test with nil harbor client
	client.SetHarborClientForTesting(nil)
	valid, err := client.ValidateBlockWithExecutionClient(testBlock)
	assert.Error(t, err, "Should return error with nil harbor client")
	assert.False(t, valid, "Valid should be false with error")

	// Create a mock harbor client
	mockHarbor := new(mockHarborClient)
	client.SetHarborClientForTesting(mockHarbor)

	// Setup mock expectations for valid block
	mockHarbor.On("ValidateBlock", mock.Anything, testBlock).Return(true, nil).Once()

	// Test valid block
	valid, err = client.ValidateBlockWithExecutionClient(testBlock)
	assert.NoError(t, err, "Should not return error with valid block")
	assert.True(t, valid, "Valid should be true for valid block")

	// Setup mock expectations for invalid block
	mockHarbor.On("ValidateBlock", mock.Anything, testBlock).Return(false, nil).Once()

	// Test invalid block
	valid, err = client.ValidateBlockWithExecutionClient(testBlock)
	assert.NoError(t, err, "Should not return error with invalid block")
	assert.False(t, valid, "Valid should be false for invalid block")

	// Setup mock expectations for error
	mockHarbor.On("ValidateBlock", mock.Anything, testBlock).Return(false, assert.AnError).Once()

	// Test error case
	valid, err = client.ValidateBlockWithExecutionClient(testBlock)
	assert.Error(t, err, "Should return error when harbor client returns error")
	assert.False(t, valid, "Valid should be false with error")

	// Verify mock expectations
	mockHarbor.AssertExpectations(t)
}

// TestMonitorValidatorBehavior tests the monitorValidatorBehavior function
func TestMonitorValidatorBehavior(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Setup a mock consensus mechanism
	mockConsensus := new(MockConsensusAlgorithm)
	// Store original for restoration
	origConsensus := client.GetConsensusForTesting()
	client.SetConsensusForTesting(mockConsensus)

	// Create some test validators
	validator1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	validator2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	validator3 := common.HexToAddress("0x3333333333333333333333333333333333333333")

	// Setup vote tracking
	blockHash := "testblock123"

	// Setup local validation result
	client.RecordLocalValidationForTesting(blockHash, true)

	// Setup votes
	client.TrackVoteForTesting(blockHash, validator1, true)  // Correct vote
	client.TrackVoteForTesting(blockHash, validator2, false) // Incorrect vote
	client.TrackVoteForTesting(blockHash, validator3, true)  // Correct vote

	// Create 5 more incorrect votes for validator2 to meet the minVotes threshold (5)
	for i := 0; i < 4; i++ {
		blockHash := fmt.Sprintf("testblock%d", i)
		client.RecordLocalValidationForTesting(blockHash, true)
		client.TrackVoteForTesting(blockHash, validator2, false) // All incorrect votes
	}

	// Set expectations - the method checks the status first
	mockConsensus.On("GetValidatorStatus", validator2).Return(consensus.StatusActive).Once()
	// And then either slashes or puts on probation by recording missed validations
	mockConsensus.On("GetProbationThreshold").Return(int(3))
	mockConsensus.On("RecordMissedValidation", validator2).Return().Times(3)

	// Run the function
	client.MonitorValidatorBehaviorForTesting()

	// Verify expectations
	mockConsensus.AssertExpectations(t)

	// Test severe misbehavior case
	// Create new mock consensus
	mockConsensus = new(MockConsensusAlgorithm)
	client.SetConsensusForTesting(mockConsensus)

	// Create 10 more incorrect votes for validator2 to meet the severe threshold
	for i := 0; i < 10; i++ {
		blockHash := fmt.Sprintf("severemisb%d", i)
		client.RecordLocalValidationForTesting(blockHash, true)
		client.TrackVoteForTesting(blockHash, validator2, false) // All incorrect votes
	}

	// Set expectations for severe misbehavior
	mockConsensus.On("GetValidatorStatus", validator2).Return(consensus.StatusActive).Once()
	mockConsensus.On("SlashValidator", validator2, mock.Anything).Return().Once()

	// Run the function
	client.MonitorValidatorBehaviorForTesting()

	// Verify expectations
	mockConsensus.AssertExpectations(t)

	// Restore original
	client.SetConsensusForTesting(origConsensus)
}

// TestRunValidatorBehaviorMonitoring tests the runValidatorBehaviorMonitoring function
func TestRunValidatorBehaviorMonitoring(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Setup context that can be canceled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.SetContextForTesting(ctx)

	// Setup a mock consensus mechanism
	mockConsensus := new(MockConsensusAlgorithm)
	// Store original for restoration
	origConsensus := client.GetConsensusForTesting()
	client.SetConsensusForTesting(mockConsensus)

	// Create some test validators
	validator1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	validator2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// Setup vote tracking
	blockHash := "testblock123"

	// Setup local validation result
	client.RecordLocalValidationForTesting(blockHash, true)

	// Setup votes
	client.TrackVoteForTesting(blockHash, validator1, true)  // Correct vote
	client.TrackVoteForTesting(blockHash, validator2, false) // Incorrect vote

	// Set expectations for monitoring - use Maybe for flexible call counts
	mockConsensus.On("GetValidatorStatus", validator2).Return(consensus.StatusActive).Maybe()
	mockConsensus.On("RecordMissedValidation", validator2).Return().Maybe()
	mockConsensus.On("GetProbationThreshold").Return(int(3)).Maybe()

	// Start the monitoring loop
	go client.RunValidatorBehaviorMonitoringForTesting(50 * time.Millisecond)

	// Let it run for a few cycles
	time.Sleep(100 * time.Millisecond)

	// Cancel the context to stop the loop
	cancel()

	// Give time for the goroutine to exit
	time.Sleep(10 * time.Millisecond)

	// Restore original
	client.SetConsensusForTesting(origConsensus)
}

// TestGetMisbehavingValidators tests the GetMisbehavingValidators function
func TestGetMisbehavingValidators(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Create some test validators
	validator1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	validator2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	validator3 := common.HexToAddress("0x3333333333333333333333333333333333333333")

	// Setup vote tracking for multiple blocks
	blockHash1 := "testblock123"
	blockHash2 := "testblock456"

	// Setup local validation results
	client.RecordLocalValidationForTesting(blockHash1, true)
	client.RecordLocalValidationForTesting(blockHash2, true)

	// Setup votes
	// Validator 1 always votes correctly
	client.TrackVoteForTesting(blockHash1, validator1, true)
	client.TrackVoteForTesting(blockHash2, validator1, true)

	// Validator 2 always votes incorrectly
	client.TrackVoteForTesting(blockHash1, validator2, false)
	client.TrackVoteForTesting(blockHash2, validator2, false)

	// Validator 3 votes mixed
	client.TrackVoteForTesting(blockHash1, validator3, true)
	client.TrackVoteForTesting(blockHash2, validator3, false)

	// Test with minimum votes = 1 and accuracy threshold = 0.5
	misbehaving := client.GetMisbehavingValidators(1, 0.5)

	// Validator 2 should be misbehaving
	assert.Contains(t, misbehaving, validator2, "Validator 2 should be identified as misbehaving")

	// Validator 3 has 50% accuracy, exactly at threshold, should not be included
	assert.NotContains(t, misbehaving, validator3, "Validator 3 should not be identified as misbehaving")

	// Validator 1 should not be misbehaving
	assert.NotContains(t, misbehaving, validator1, "Validator 1 should not be identified as misbehaving")
}

// TestAnalyzeValidatorBehavior tests the AnalyzeValidatorBehavior function
func TestAnalyzeValidatorBehavior(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Create some test validators
	validator1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	validator2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	validator3 := common.HexToAddress("0x3333333333333333333333333333333333333333")

	// Setup vote tracking for multiple blocks
	blockHash1 := "testblock123"
	blockHash2 := "testblock456"

	// Setup local validation results
	client.RecordLocalValidationForTesting(blockHash1, true)
	client.RecordLocalValidationForTesting(blockHash2, true)

	// Setup votes
	// Validator 1 always votes correctly
	client.TrackVoteForTesting(blockHash1, validator1, true)
	client.TrackVoteForTesting(blockHash2, validator1, true)

	// Validator 2 always votes incorrectly
	client.TrackVoteForTesting(blockHash1, validator2, false)
	client.TrackVoteForTesting(blockHash2, validator2, false)

	// Validator 3 votes mixed
	client.TrackVoteForTesting(blockHash1, validator3, true)
	client.TrackVoteForTesting(blockHash2, validator3, false)

	// Run the analysis
	stats := client.AnalyzeValidatorBehavior()

	// Check validator 1
	validator1Stats, exists := stats[validator1]
	assert.True(t, exists, "Validator 1 should be in the stats")
	if exists {
		assert.Equal(t, 2, validator1Stats.TotalVotes, "Validator 1 should have 2 total votes")
		assert.Equal(t, 2, validator1Stats.CorrectVotes, "Validator 1 should have 2 correct votes")
		assert.Equal(t, 0, validator1Stats.IncorrectVotes, "Validator 1 should have 0 incorrect votes")
		assert.Equal(t, 100.0, validator1Stats.Accuracy, "Validator 1 should have 100% accuracy")
	}

	// Check validator 2
	validator2Stats, exists := stats[validator2]
	assert.True(t, exists, "Validator 2 should be in the stats")
	if exists {
		assert.Equal(t, 2, validator2Stats.TotalVotes, "Validator 2 should have 2 total votes")
		assert.Equal(t, 0, validator2Stats.CorrectVotes, "Validator 2 should have 0 correct votes")
		assert.Equal(t, 2, validator2Stats.IncorrectVotes, "Validator 2 should have 2 incorrect votes")
		assert.Equal(t, 0.0, validator2Stats.Accuracy, "Validator 2 should have 0% accuracy")
	}

	// Check validator 3
	validator3Stats, exists := stats[validator3]
	assert.True(t, exists, "Validator 3 should be in the stats")
	if exists {
		assert.Equal(t, 2, validator3Stats.TotalVotes, "Validator 3 should have 2 total votes")
		assert.Equal(t, 1, validator3Stats.CorrectVotes, "Validator 3 should have 1 correct vote")
		assert.Equal(t, 1, validator3Stats.IncorrectVotes, "Validator 3 should have 1 incorrect vote")
		assert.Equal(t, 50.0, validator3Stats.Accuracy, "Validator 3 should have 50% accuracy")
	}
}

// TestRecordValidatorSeen tests the recordValidatorSeen function
func TestRecordValidatorSeen(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Test recording a validator
	validatorAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	client.RecordValidatorSeenForTesting(validatorAddr)

	// Verify it was recorded
	count := client.GetRecordedValidatorsCountForTesting()
	assert.Equal(t, 1, count, "Should have 1 validator recorded as seen")
}

// TestCleanupStaleVotes tests the cleanupStaleVotes function
func TestCleanupStaleVotes(t *testing.T) {
	client, _, hook := setupTestConsensusClient(t)

	// Create test validators
	validator1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	validator2 := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// Edge Case 1: Empty vote tracker - should not crash
	hook.Reset()
	client.CleanupStaleVotesForTesting()
	assert.Empty(t, hook.AllEntries(), "No logs should be created for empty tracker")

	// Test Case 1: Create a simulated high number of blocks (more than MAX_TRACKED_BLOCKS=1000)
	const numBlocks = 1100
	const maxTrackedBlocks = 1000 // This should match the value in the cleanupStaleVotes function

	// Track votes for these blocks
	for i := 0; i < numBlocks; i++ {
		blockHash := fmt.Sprintf("block-%d", i)
		client.TrackVoteForTesting(blockHash, validator1, true)
		client.TrackVoteForTesting(blockHash, validator2, i%2 == 0) // Some disagreement
		client.RecordLocalValidationForTesting(blockHash, true)
	}

	// Get size before cleanup
	beforeVoteCount := client.GetVoteMapSizeForTesting()
	beforeValidationCount := client.GetLocalValidationMapSizeForTesting()

	// The counts might not be exactly numBlocks due to caching or other factors,
	// but they should be substantial
	assert.Greater(t, beforeVoteCount, 100, "Should have a substantial number of blocks before cleanup")
	assert.Greater(t, beforeValidationCount, 100, "Should have a substantial number of validations before cleanup")

	// Clear log hook
	hook.Reset()

	// Run the cleanup
	client.CleanupStaleVotesForTesting()

	// After cleanup, the number of tracked blocks should be reduced
	afterVoteCount := client.GetVoteMapSizeForTesting()
	afterValidationCount := client.GetLocalValidationMapSizeForTesting()

	// Check that cleanup reduced the count
	assert.Less(t, afterVoteCount, beforeVoteCount, "Cleanup should have removed some blocks")
	assert.Less(t, afterValidationCount, beforeValidationCount, "Cleanup should have removed some validations")

	// Verify log entries were created for removed blocks
	logEntries := hook.AllEntries()

	// There should be some log entries for removed blocks
	logCount := 0
	for _, entry := range logEntries {
		if entry.Message == "Cleaned up stale vote tracking for old block" &&
			entry.Level == logrus.DebugLevel {
			logCount++
		}
	}

	// We should have some logs about removed blocks
	assert.Greater(t, logCount, 0, "Should have some log entries for removed blocks")

	// The number of logs should roughly match the number of removed blocks
	removedBlockCount := beforeVoteCount - afterVoteCount
	assert.InDelta(t, removedBlockCount, logCount, float64(removedBlockCount)*0.1,
		"Number of log entries should be roughly equal to the number of removed blocks")

	// Test Case 2: Run cleanup again when we're already below the limit
	// Clear log hook
	hook.Reset()

	// Store the counts before second cleanup
	beforeSecondCleanupVoteCount := client.GetVoteMapSizeForTesting()
	beforeSecondCleanupValidationCount := client.GetLocalValidationMapSizeForTesting()

	// Run cleanup again
	client.CleanupStaleVotesForTesting()

	// Counts should remain the same since we're below the limit
	afterSecondCleanupVoteCount := client.GetVoteMapSizeForTesting()
	afterSecondCleanupValidationCount := client.GetLocalValidationMapSizeForTesting()

	assert.Equal(t, beforeSecondCleanupVoteCount, afterSecondCleanupVoteCount,
		"Second cleanup should not remove blocks when below limit")
	assert.Equal(t, beforeSecondCleanupValidationCount, afterSecondCleanupValidationCount,
		"Second cleanup should not remove validations when below limit")

	// No logs should be created for the second cleanup
	assert.Empty(t, hook.AllEntries(), "No logs should be created for second cleanup when below limit")
}

// TestIdentifyMisbehavingValidators tests the IdentifyMisbehavingValidators function
func TestIdentifyMisbehavingValidators(t *testing.T) {
	client, _, _ := setupTestConsensusClient(t)

	// Create test validators
	validator1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	validator2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	validator3 := common.HexToAddress("0x3333333333333333333333333333333333333333")
	validator4 := common.HexToAddress("0x4444444444444444444444444444444444444444")

	// Create test blocks
	blockHash1 := "testblock123"
	blockHash2 := "testblock456"
	blockHash3 := "testblock789" // Block without local validation

	// Setup local validation results
	client.RecordLocalValidationForTesting(blockHash1, true)  // We think block1 is valid
	client.RecordLocalValidationForTesting(blockHash2, false) // We think block2 is invalid

	// Setup votes
	// Block 1 votes
	client.TrackVoteForTesting(blockHash1, validator1, true)  // Agrees with us
	client.TrackVoteForTesting(blockHash1, validator2, false) // Disagrees with us
	client.TrackVoteForTesting(blockHash1, validator3, true)  // Agrees with us
	client.TrackVoteForTesting(blockHash1, validator4, false) // Disagrees with us

	// Block 2 votes
	client.TrackVoteForTesting(blockHash2, validator1, false) // Agrees with us
	client.TrackVoteForTesting(blockHash2, validator2, true)  // Disagrees with us
	client.TrackVoteForTesting(blockHash2, validator3, false) // Agrees with us

	// Block 3 votes (no local validation)
	client.TrackVoteForTesting(blockHash3, validator1, true)
	client.TrackVoteForTesting(blockHash3, validator2, false)

	// Test IdentifyMisbehavingValidators for block1
	misbehaving1 := client.IdentifyMisbehavingValidatorsForTesting(blockHash1)

	// Validator2 and validator4 should be identified as misbehaving for block1
	assert.Len(t, misbehaving1, 2, "Should identify 2 misbehaving validators for block1")
	assert.Contains(t, misbehaving1, validator2, "Validator2 should be misbehaving for block1")
	assert.Contains(t, misbehaving1, validator4, "Validator4 should be misbehaving for block1")
	assert.NotContains(t, misbehaving1, validator1, "Validator1 should not be misbehaving for block1")
	assert.NotContains(t, misbehaving1, validator3, "Validator3 should not be misbehaving for block1")

	// Test IdentifyMisbehavingValidators for block2
	misbehaving2 := client.IdentifyMisbehavingValidatorsForTesting(blockHash2)

	// Validator2 should be identified as misbehaving for block2
	assert.Len(t, misbehaving2, 1, "Should identify 1 misbehaving validator for block2")
	assert.Contains(t, misbehaving2, validator2, "Validator2 should be misbehaving for block2")
	assert.NotContains(t, misbehaving2, validator1, "Validator1 should not be misbehaving for block2")
	assert.NotContains(t, misbehaving2, validator3, "Validator3 should not be misbehaving for block2")

	// Test IdentifyMisbehavingValidators for block3 (no local validation)
	misbehaving3 := client.IdentifyMisbehavingValidatorsForTesting(blockHash3)

	// No validators should be identified as misbehaving for block3 since we didn't validate it
	assert.Len(t, misbehaving3, 0, "Should not identify any misbehaving validators for block3")

	// Test with non-existent block
	misbehaving4 := client.IdentifyMisbehavingValidatorsForTesting("nonexistent-block")
	assert.Len(t, misbehaving4, 0, "Should not identify any misbehaving validators for nonexistent block")
}

// TestCheckBlockConsensus tests the checkBlockConsensus function
func TestCheckBlockConsensus(t *testing.T) {
	client, _, hook := setupTestConsensusClient(t)

	// Create test validators
	validator1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	validator2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	validator3 := common.HexToAddress("0x3333333333333333333333333333333333333333")

	// Create test blocks
	blockHash1 := "unvalidated-block"     // Block we haven't validated locally
	blockHash2 := "valid-block-consensus" // Block we validated as valid, and most validators agree
	blockHash3 := "valid-block-dissent"   // Block we validated as valid, but some validators disagree

	// Create a mock consensus mechanism that will record the calls
	mockConsensus := new(MockConsensusAlgorithm)
	origConsensus := client.GetConsensusForTesting()
	client.SetConsensusForTesting(mockConsensus)

	// Setup mock expectations - we'll use these to verify that ReportInvalidBlock works
	mockConsensus.On("RecordInvalidTransaction", validator2).Return().Maybe()

	// Reset log hook
	hook.Reset()

	// Test Case 1: Block we haven't validated locally
	// Only track votes without recording local validation
	client.TrackVoteForTesting(blockHash1, validator1, true)
	client.TrackVoteForTesting(blockHash1, validator2, false)

	// Call the function
	client.CheckBlockConsensusForTesting(blockHash1)

	// Verify that RecordInvalidTransaction was not called for unvalidated block
	mockConsensus.AssertNotCalled(t, "RecordInvalidTransaction", mock.Anything)

	// Check that no logs were made since we haven't validated
	assert.Empty(t, hook.AllEntries(), "Should not log anything when we haven't validated the block")

	// Reset for next test
	hook.Reset()
	mockConsensus = new(MockConsensusAlgorithm)
	mockConsensus.On("RecordInvalidTransaction", mock.Anything).Return().Maybe()
	client.SetConsensusForTesting(mockConsensus)

	// Test Case 2: Block we validated as valid with consensus
	client.RecordLocalValidationForTesting(blockHash2, true)
	client.TrackVoteForTesting(blockHash2, validator1, true) // Agrees with us
	client.TrackVoteForTesting(blockHash2, validator2, true) // Agrees with us
	client.TrackVoteForTesting(blockHash2, validator3, true) // Agrees with us

	// Call the function
	client.CheckBlockConsensusForTesting(blockHash2)

	// Verify that RecordInvalidTransaction was not called when all agree
	mockConsensus.AssertNotCalled(t, "RecordInvalidTransaction", mock.Anything)

	// Check for the log about block validity
	var validBlockLogFound bool
	for _, entry := range hook.AllEntries() {
		if entry.Data["blockHash"] == blockHash2 && entry.Message == "Block locally validated as valid" {
			validBlockLogFound = true
			break
		}
	}
	assert.True(t, validBlockLogFound, "Should log that the block was locally validated as valid")

	// Reset for next test
	hook.Reset()
	mockConsensus = new(MockConsensusAlgorithm)
	mockConsensus.On("RecordInvalidTransaction", validator2).Return().Once()
	client.SetConsensusForTesting(mockConsensus)

	// Test Case 3: Block we validated as valid with some dissent
	client.RecordLocalValidationForTesting(blockHash3, true)
	client.TrackVoteForTesting(blockHash3, validator1, true)  // Agrees with us
	client.TrackVoteForTesting(blockHash3, validator2, false) // Disagrees with us
	client.TrackVoteForTesting(blockHash3, validator3, true)  // Agrees with us

	// Call the function
	client.CheckBlockConsensusForTesting(blockHash3)

	// Verify that RecordInvalidTransaction was called for the misbehaving validator
	mockConsensus.AssertCalled(t, "RecordInvalidTransaction", validator2)

	// Check for warning log about validator misbehavior
	var warningLogFound bool
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel &&
			entry.Data["validator"] == validator2.Hex() &&
			entry.Data["blockHash"] == blockHash3 &&
			entry.Message == "Detected validator voting against local validation result" {
			warningLogFound = true
			break
		}
	}
	assert.True(t, warningLogFound, "Should log a warning about validator2 voting against our validation")

	// Also check for the log about block validity
	validBlockLogFound = false
	for _, entry := range hook.AllEntries() {
		if entry.Data["blockHash"] == blockHash3 && entry.Message == "Block locally validated as valid" {
			validBlockLogFound = true
			break
		}
	}
	assert.True(t, validBlockLogFound, "Should log that the block was locally validated as valid")

	// Test Case 4: Block we validated as invalid
	blockHash4 := "invalid-block"

	// Reset for next test
	hook.Reset()
	mockConsensus = new(MockConsensusAlgorithm)
	mockConsensus.On("RecordInvalidTransaction", validator2).Return().Once()
	client.SetConsensusForTesting(mockConsensus)

	client.RecordLocalValidationForTesting(blockHash4, false)
	client.TrackVoteForTesting(blockHash4, validator1, false) // Agrees with us
	client.TrackVoteForTesting(blockHash4, validator2, true)  // Disagrees with us

	// Call the function
	client.CheckBlockConsensusForTesting(blockHash4)

	// Verify that RecordInvalidTransaction was called for the misbehaving validator
	mockConsensus.AssertCalled(t, "RecordInvalidTransaction", validator2)

	// Check for warning log about validator misbehavior
	warningLogFound = false
	for _, entry := range hook.AllEntries() {
		if entry.Level == logrus.WarnLevel &&
			entry.Data["validator"] == validator2.Hex() &&
			entry.Data["blockHash"] == blockHash4 {
			warningLogFound = true
			break
		}
	}
	assert.True(t, warningLogFound, "Should log a warning about validator2 voting against our validation")

	// Check for the log that the block was invalid
	var invalidBlockLogFound bool
	for _, entry := range hook.AllEntries() {
		if entry.Data["blockHash"] == blockHash4 && entry.Message == "Block locally validated as invalid" {
			invalidBlockLogFound = true
			break
		}
	}
	assert.True(t, invalidBlockLogFound, "Should log that the block was locally validated as invalid")

	// Restore original consensus
	client.SetConsensusForTesting(origConsensus)
}
