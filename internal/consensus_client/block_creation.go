package consensus_client

import (
	"blockchain-simulator/internal/blockchain"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

// RequestBlockFromExecutionClient requests the execution client to create a new block
// from its transaction pool when this node is selected as the validator
func (c *ConsensusClient) RequestBlockFromExecutionClient() (*blockchain.Block, error) {
	// Check if we have a harbor client
	if c.harborClient == nil {
		return nil, fmt.Errorf("no Harbor client available")
	}

	c.logger.Info("Requesting block creation via Harbor API")

	// Request block creation with a maximum of 100 transactions
	// In a real implementation, you might want to configure this
	maxTransactions := uint32(100)

	block, err := c.harborClient.RequestBlockCreation(c.ctx, c.selfAddress, maxTransactions)
	if err != nil {
		return nil, fmt.Errorf("failed to request block via Harbor API: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"blockHash":  block.Hash,
		"blockIndex": block.Index,
		"txCount":    len(block.Transactions),
	}).Info("Successfully received block from execution client")

	return block, nil
}

// ValidateBlockWithExecutionClient sends a block to the execution client for validation
func (c *ConsensusClient) ValidateBlockWithExecutionClient(block *blockchain.Block) (bool, error) {
	// Check if we have a harbor client
	if c.harborClient == nil {
		return false, fmt.Errorf("no Harbor client available")
	}

	c.logger.WithFields(logrus.Fields{
		"blockHash":  block.Hash,
		"blockIndex": block.Index,
	}).Info("Sending block to execution client for validation via Harbor API")

	valid, err := c.harborClient.ValidateBlock(c.ctx, block)
	if err != nil {
		return false, fmt.Errorf("failed to validate block via Harbor API: %w", err)
	}

	if !valid {
		c.logger.WithField("blockHash", block.Hash).Warn("Block validation failed at execution client")
		return false, nil
	}

	c.logger.WithField("blockHash", block.Hash).Info("Block successfully validated by execution client")
	return true, nil
}

// runValidatorSelectionLoop periodically selects a validator for the next block
func (c *ConsensusClient) runValidatorSelectionLoop() {
	// Initialize variables for tracking validator selection
	var lastSelectedValidator common.Address
	var lastSelectionTime time.Time
	var missedValidations map[common.Address]time.Time = make(map[common.Address]time.Time)

	// Get the slot duration from consensus
	slotDuration := c.Consensus.GetSlotDuration()

	// If genesis timestamp is 0, use current time as genesis
	if c.genesisTimestamp == 0 {
		c.logger.Warn("No genesis timestamp set, using current time")
		c.genesisTimestamp = uint64(time.Now().Unix())
	}

	// Calculate the time until the next slot
	genesisTime := time.Unix(int64(c.genesisTimestamp), 0)
	now := time.Now()

	c.logger.WithFields(logrus.Fields{
		"genesisTime":  genesisTime,
		"slotDuration": slotDuration,
	}).Info("Synchronizing validator selection loop with genesis timestamp")

	// Calculate elapsed time since genesis
	elapsed := now.Sub(genesisTime)

	// Calculate the next slot time
	// Find how many complete slots have passed since genesis
	completedSlots := elapsed / slotDuration
	// Calculate the start time of the next slot
	nextSlotTime := genesisTime.Add(slotDuration * (completedSlots + 1))

	// Time to wait until the next slot begins
	timeToWait := nextSlotTime.Sub(now)

	c.logger.WithFields(logrus.Fields{
		"completedSlots": completedSlots,
		"nextSlotTime":   nextSlotTime,
		"timeToWait":     timeToWait,
	}).Info("Waiting for next slot to begin validator selection")

	// Wait until the next slot starts
	time.Sleep(timeToWait)

	// Start the ticker exactly at the slot boundary
	ticker := time.NewTicker(slotDuration)
	defer ticker.Stop()

	// Log that we're starting the selection loop
	c.logger.WithFields(logrus.Fields{
		"firstTickTime": time.Now(),
		"slotDuration":  slotDuration,
	}).Info("Starting validator selection loop synchronized with genesis")

	// Select a validator immediately for the first slot
	c.selectAndProcessValidator(&lastSelectedValidator, &lastSelectionTime, missedValidations)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.selectAndProcessValidator(&lastSelectedValidator, &lastSelectionTime, missedValidations)
		}
	}
}

// selectAndProcessValidator handles validator selection and processing
// Extracted from runValidatorSelectionLoop to avoid code duplication
func (c *ConsensusClient) selectAndProcessValidator(
	lastSelectedValidator *common.Address,
	lastSelectionTime *time.Time,
	missedValidations map[common.Address]time.Time) {

	validator := c.Consensus.SelectValidator()

	// Check if the previously selected validator should have produced a block
	if *lastSelectedValidator != (common.Address{}) &&
		*lastSelectedValidator != c.selfAddress { // Don't report ourselves

		// Check if we're past the expected block time and haven't received a block
		timeElapsed := time.Since(*lastSelectionTime)
		if timeElapsed > c.Consensus.GetSlotDuration() {
			// If we previously marked this validator, check if it's time to report
			if lastMarked, exists := missedValidations[*lastSelectedValidator]; exists {
				// If it's been more than one full slot since we marked them, report
				if time.Since(lastMarked) >= c.Consensus.GetSlotDuration() {
					c.ReportMissedValidation(*lastSelectedValidator)
					c.logger.WithFields(logrus.Fields{
						"validator": lastSelectedValidator.Hex(),
						"elapsed":   timeElapsed,
					}).Info("Reporting validator for missed block production")

					// Remove from our tracking map after reporting
					delete(missedValidations, *lastSelectedValidator)
				}
			} else {
				// Mark this validator as potentially missing their slot
				missedValidations[*lastSelectedValidator] = time.Now()
			}
		}
	}

	// Update for the next cycle
	*lastSelectedValidator = validator
	*lastSelectionTime = time.Now()

	// Check if we are the selected validator
	if validator == c.selfAddress {
		c.logger.WithFields(logrus.Fields{
			"validator": validator.Hex(),
			"slotTime":  *lastSelectionTime,
		}).Info("We are the selected validator for this slot")

		// Request a block from the execution client
		if c.harborClient != nil {
			go func() {
				block, err := c.RequestBlockFromExecutionClient()
				if err != nil {
					c.logger.WithError(err).Error("Failed to get block from execution client")
					return
				}

				// Propose the block to the network
				if err := c.ProposeBlock(block); err != nil {
					c.logger.WithError(err).Error("Failed to propose block")
					return
				}

				c.logger.WithFields(logrus.Fields{
					"blockHash":  block.Hash,
					"blockIndex": block.Index,
					"txCount":    len(block.Transactions),
				}).Info("Successfully proposed block to the network")
			}()
		} else {
			c.logger.Warn("No execution client available to create block")
		}
	} else {
		c.logger.WithFields(logrus.Fields{
			"validator": validator.Hex(),
			"slotTime":  *lastSelectionTime,
		}).Info("Selected validator for this slot")
	}
}
