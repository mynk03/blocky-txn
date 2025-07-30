package consensus_client

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

// ReportMissedValidation reports that a validator missed their validation slot
func (c *ConsensusClient) ReportMissedValidation(validator common.Address) error {
	evidence := EvidenceData{
		Validator:    validator,
		EvidenceType: ValidationMissed,
		Reason:       "Validator missed their validation slot",
	}

	msg := ConsensusMessage{
		Type:      ValidationMissed,
		Sender:    c.selfAddress,
		Evidence:  &evidence,
		Timestamp: time.Now(),
	}

	// Record the missed validation in the consensus mechanism
	c.Consensus.RecordMissedValidation(validator)

	c.logger.WithFields(logrus.Fields{
		"validator": validator.Hex(),
	}).Info("Missed block production recorded")

	// Attempt to publish, but don't fail if this doesn't work
	// (e.g., during tests or when the network is down)
	if err := c.publishMessage(msg); err != nil {
		c.logger.WithError(err).Debug("Failed to publish missed validation report")
		return err
	}

	return nil
}

// ReportDoubleSign reports evidence of a validator double signing
func (c *ConsensusClient) ReportDoubleSign(validator common.Address, blockHash string) error {
	evidence := EvidenceData{
		Validator:    validator,
		EvidenceType: DoubleSignEvidence,
		BlockHash:    blockHash,
		Reason:       "Validator signed multiple blocks at the same height",
	}

	msg := ConsensusMessage{
		Type:      DoubleSignEvidence,
		Sender:    c.selfAddress,
		Evidence:  &evidence,
		Timestamp: time.Now(),
	}

	// Record the double sign in the consensus mechanism
	c.Consensus.RecordDoubleSign(validator)

	return c.publishMessage(msg)
}

// ReportInvalidBlock reports evidence of a validator proposing an invalid block
func (c *ConsensusClient) ReportInvalidBlock(validator common.Address, blockHash string, reason string) error {
	evidence := EvidenceData{
		Validator:    validator,
		EvidenceType: InvalidBlockEvidence,
		BlockHash:    blockHash,
		Reason:       reason,
	}

	msg := ConsensusMessage{
		Type:      InvalidBlockEvidence,
		Sender:    c.selfAddress,
		Evidence:  &evidence,
		Timestamp: time.Now(),
	}

	// Record the invalid transaction in the consensus mechanism
	c.Consensus.RecordInvalidTransaction(validator)

	return c.publishMessage(msg)
}
