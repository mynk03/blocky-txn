// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package main

import (
	consensus "blockchain-simulator/internal/consensus_client"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Configuration holds all settings for the consensus client
type Configuration struct {
	ListenAddr   string // Address to listen on for P2P connections
	InitialStake uint64 // Initial stake amount for validator
	LogLevel     string // Log level (debug, info, warn, error)
	HarborAddr   string // Harbor service address for execution client
	ValidatorKey string // Validator private key (hex without 0x prefix)
}

// DefaultConfiguration returns the default configuration
func DefaultConfiguration() Configuration {
	return Configuration{
		ListenAddr:   "/ip4/127.0.0.1/tcp/9000",
		InitialStake: 200,
		LogLevel:     "info",
	}
}

// LoadConfigFromEnv loads configuration from environment variables and config files
func loadConfigFromEnv() Configuration {
	// Initialize Viper
	v := viper.New()

	// Set default values
	v.SetDefault("listen_addr", "/ip4/127.0.0.1/tcp/9000")
	v.SetDefault("initial_stake", 200)
	v.SetDefault("log_level", "info")
	v.SetDefault("harbor_service_addr", "")
	v.SetDefault("validator_private_key", "")

	// Set environment variable prefix and bind environment variables
	v.SetEnvPrefix("") // No prefix for backward compatibility
	v.AutomaticEnv()   // Automatically bind to environment variables

	// Replace dots and dashes in environment variables with underscores
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// Try to find and read .env file
	v.SetConfigName(".env")                               // name of config file (without extension)
	v.SetConfigType("env")                                // REQUIRED if the config file does not have the extension in the name
	v.AddConfigPath(".")                                  // look for config in the working directory
	v.AddConfigPath("$HOME/.config/blockchain-simulator") // look in home directory

	// Handle config file reading errors gracefully
	if err := v.ReadInConfig(); err != nil {
		// It's okay if config file doesn't exist
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Printf("Warning: Error reading config file: %s\n", err)
		}
	}

	// Create configuration from Viper
	config := Configuration{
		ListenAddr:   v.GetString("listen_addr"),
		InitialStake: v.GetUint64("initial_stake"),
		LogLevel:     v.GetString("log_level"),
		HarborAddr:   v.GetString("harbor_service_addr"),
		ValidatorKey: v.GetString("validator_private_key"),
	}

	return config
}

func main() {
	config := loadConfigFromEnv()
	err := runConsensusClient(config)
	if err != nil {
		logrus.Fatalf("Failed to run consensus client: %v", err)
	}
}

// RunConsensusClient initializes and runs the consensus client with the given configuration
func runConsensusClient(config Configuration) error {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})

	// Set log level
	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		logger.WithError(err).Warn("Invalid log level, defaulting to 'info'")
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Log configuration
	logger.WithFields(logrus.Fields{
		"listenAddr":   config.ListenAddr,
		"initialStake": config.InitialStake,
		"logLevel":     config.LogLevel,
		"harborAddr":   config.HarborAddr,
		"validatorKey": anonymizeKey(config.ValidatorKey),
	}).Info("Loaded configuration")

	// Set Harbor address in environment if provided
	if config.HarborAddr != "" {
		os.Setenv("HARBOR_SERVICE_ADDR", config.HarborAddr)
		logger.WithField("address", config.HarborAddr).Info("Setting Harbor service address from configuration")
	}

	// Set validator private key if provided
	if config.ValidatorKey != "" {
		os.Setenv("VALIDATOR_PRIVATE_KEY", config.ValidatorKey)
		logger.WithField("key", anonymizeKey(config.ValidatorKey)).Info("Using validator private key from configuration")
	}

	// Create the consensus client
	logger.Info("Creating consensus client...")
	client, err := consensus.NewConsensusClient(config.ListenAddr, config.InitialStake, logger)
	if err != nil {
		return fmt.Errorf("failed to create consensus client: %w", err)
	}

	// Start the consensus client
	logger.Info("Starting consensus client...")
	if err := client.Start(); err != nil {
		return fmt.Errorf("failed to start consensus client: %w", err)
	}

	// Log successful startup
	logger.WithFields(logrus.Fields{
		"listenAddress": config.ListenAddr,
		"initialStake":  config.InitialStake,
		"validator":     client.GetValidatorAddress().Hex(),
	}).Info("Consensus client started successfully")

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Gracefully shut down
	logger.Info("Shutting down consensus client...")
	if err := client.Stop(); err != nil {
		logger.WithError(err).Error("Error stopping consensus client")
	}
	logger.Info("Consensus client stopped")

	return nil
}

// anonymizeKey masks a key string for secure logging
func anonymizeKey(key string) string {
	if key == "" {
		return "not provided"
	}
	if len(key) <= 8 {
		return "***masked***"
	}
	// Show only the first and last 4 characters
	return key[:4] + "..." + key[len(key)-4:]
}
