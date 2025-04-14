package consensus_client

import (
	"blockchain-simulator/consensus"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

// AnnounceValidator broadcasts this node's validator status to the network
func (c *ConsensusClient) AnnounceValidator() error {
	// Get current stake amount
	stake := c.Consensus.GetValidatorStake(c.selfAddress)

	// Only announce if we have sufficient stake
	if stake == 0 {
		return fmt.Errorf("not a validator, insufficient stake to announce")
	}

	// Get validator metrics
	metrics := c.Consensus.GetValidatorMetrics(c.selfAddress)
	if metrics == nil {
		// Create default metrics if none exist
		metrics = &consensus.ValidationMetrics{
			Status:         consensus.StatusActive,
			LastActiveTime: time.Now(),
		}
	}

	// Record our own validator as seen
	c.recordValidatorSeen(c.selfAddress)

	// Create and publish announcement message
	msg := ConsensusMessage{
		Type:             ValidatorAnnouncement,
		Sender:           c.selfAddress,
		ValidatorAddress: c.selfAddress,
		ValidatorStake:   stake,
		ValidatorMetrics: metrics,
		Timestamp:        time.Now(),
	}

	return c.publishMessage(msg)
}

// runValidatorAnnouncementLoop periodically announces validator status
func (c *ConsensusClient) runValidatorAnnouncementLoop() {
	// Announce once immediately
	if err := c.AnnounceValidator(); err != nil {
		c.logger.WithError(err).Debug("Failed to announce validator status")
	}

	// Then announce periodically
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				if err := c.AnnounceValidator(); err != nil {
					c.logger.WithError(err).Debug("Failed to announce validator status")
				}
			}
		}
	}()

	c.logger.Debug("Started validator announcement loop")
}

// processValidatorAnnouncement handles validator announcements from other nodes
func (c *ConsensusClient) processValidatorAnnouncement(validatorAddress common.Address, stake uint64, metrics *consensus.ValidationMetrics, sender common.Address) {
	if validatorAddress == (common.Address{}) {
		c.logger.Error("Received empty validator announcement")
		return
	}

	c.logger.WithFields(logrus.Fields{
		"validator": validatorAddress.Hex(),
		"stake":     stake,
		"status":    metrics.Status.String(),
		"sender":    sender.Hex(),
	}).Info("Received validator announcement")

	// Record when this validator was last seen
	c.recordValidatorSeen(validatorAddress)

	// In a production system, we would:
	// 1. Verify the signature to confirm ownership
	// 2. Check if the stake matches what's recorded on-chain

	// For this simulator, we'll trust the announcement and update our local consensus

	// Add or update the validator in our local consensus
	// Note: we're using the announced stake directly, but in a real system
	// this would be verified against an on-chain record
	c.Consensus.Deposit(validatorAddress, stake)

	// Update status if needed
	currentStatus := c.Consensus.GetValidatorStatus(validatorAddress)

	// Only update status if the announced status is different
	if currentStatus != metrics.Status {
		switch metrics.Status {
		case consensus.StatusProbation:
			if currentStatus != consensus.StatusProbation {
				// Set validator on probation (simplified)
				for i := 0; i < int(c.Consensus.GetProbationThreshold()); i++ {
					c.Consensus.RecordMissedValidation(validatorAddress)
				}
			}
		case consensus.StatusSlashed:
			if currentStatus != consensus.StatusSlashed {
				c.Consensus.SlashValidator(validatorAddress, "Reported as slashed by peer")
			}
		}
	}
}

// recordValidatorSeen updates the last time a validator was seen
func (c *ConsensusClient) recordValidatorSeen(validator common.Address) {
	c.lastSeenMutex.Lock()
	defer c.lastSeenMutex.Unlock()

	c.lastSeenValidators[validator] = time.Now()
}

// monitorOfflineValidators periodically checks for validators that haven't been seen recently
func (c *ConsensusClient) monitorOfflineValidators() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkOfflineValidators()
		}
	}
}

// checkOfflineValidators checks for validators that haven't been seen recently and reports them
func (c *ConsensusClient) checkOfflineValidators() {
	now := time.Now()
	offlineThreshold := now.Add(-c.validatorOfflineThreshold)

	// Get all active validators
	validators := c.Consensus.GetValidatorSet()

	c.lastSeenMutex.RLock()
	for _, validator := range validators {
		// Skip our own address
		if validator == c.selfAddress {
			continue
		}

		lastSeen, exists := c.lastSeenValidators[validator]
		if !exists || lastSeen.Before(offlineThreshold) {
			// This validator hasn't been seen recently
			c.lastSeenMutex.RUnlock() // Unlock before making the call to avoid deadlock

			// Get current status to avoid unnecessary reports
			status := c.Consensus.GetValidatorStatus(validator)
			if status == consensus.StatusActive {
				// Report the missed validation
				c.ReportMissedValidation(validator)

				c.logger.WithFields(logrus.Fields{
					"validator": validator.Hex(),
					"lastSeen":  lastSeen,
				}).Info("Reporting validator as offline due to missed announcements")
			}

			c.lastSeenMutex.RLock() // Lock again to continue iteration
		}
	}
	c.lastSeenMutex.RUnlock()
}
