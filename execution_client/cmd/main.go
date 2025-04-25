// Copyright (c) 2025 ANCILAR
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

package main

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/execution_client"
	"blockchain-simulator/transaction"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

func main() {
	// Load .env file
	godotenv.Load()

	// Setup logger
	logger := setupLogger(getEnv("LOG_LEVEL", "info"))
	logger.Info("Starting execution client node...")

	// Get configuration from environment
	dataDir := getEnv("DATA_DIR", "./chain_data/node0")
	httpPort := getEnv("HTTP_PORT", "8080")
	harborPort := getEnv("HARBOR_PORT", "50050")
	listenAddr := getEnv("LISTEN_ADDR", "/ip4/127.0.0.1/tcp/0")
	validatorKey := getEnv("VALIDATOR_PRIVATE_KEY", "9ed1cbd1eaf58283b752faf8e967ed74538624b023eee4a3469346e34fd22036") // default private key for validator

	fmt.Println("validatorKey: ", validatorKey)

	walletsPath := getEnv("WALLETS_PATH", "chain_data/genesis_data/initial_users/mock_wallets.json")

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		logger.Fatalf("Failed to create data directory: %v", err)
	}

	// Convert private key to ECDSA
	privateKey, err := crypto.HexToECDSA(validatorKey)
	if err != nil {
		logger.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	validatorAddr := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Initialize blockchain storage
	storage, err := blockchain.NewLevelDBStorage(filepath.Join(dataDir, "blockchain"))
	if err != nil {
		logger.Fatalf("Failed to create blockchain storage: %v", err)
	}
	defer storage.Close()

	addresses, balances := getAddressFromMockWallets(walletsPath)

	// Create blockchain with initial validator account
	chain := blockchain.NewBlockchain(storage, addresses, balances)

	// Create transaction pool
	txPool := transaction.NewTransactionPool()

	// Create Harbor server
	harborServer := execution_client.NewHarborServer(txPool, chain, validatorAddr.Hex(), logger)

	// Create execution client
	client, err := execution_client.NewExecutionClient(
		listenAddr,
		txPool,
		chain,
		validatorAddr,
		harborServer,
		logger,
	)
	if err != nil {
		logger.Fatalf("Failed to create execution client: %v", err)
	}

	// Create HTTP server
	httpServer := execution_client.NewServer(client)

	// Start execution client
	if err := client.Start(harborPort, httpServer, httpPort); err != nil {
		logger.Fatalf("Failed to start execution client: %v", err)
	}

	// Print node information
	logger.Infof("Node started successfully")
	logger.Infof("HTTP server listening on :%s", httpPort)
	logger.Infof("Harbor RPC server listening on :%s", harborPort)
	logger.Infof("P2P address: %s", client.GetAddress())

	// Wait for interrupt signal
	waitForInterrupt(logger, client)
}

func setupLogger(level string) *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Set log level
	switch level {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	return logger
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func waitForInterrupt(logger *logrus.Logger, client *execution_client.ExecutionClient) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt signal
	sig := <-sigCh
	logger.Infof("Received signal %v, shutting down...", sig)

	// Stop the client
	if err := client.Stop(); err != nil {
		logger.Errorf("Error stopping client: %v", err)
	}

	logger.Info("Node shutdown complete")
}

// Get the address from mock_wallets.json
func getAddressFromMockWallets(path string) ([]string, []uint64) {
	// Read the JSON file
	data, err := os.ReadFile(path)

	if err != nil {
		log.Fatalf("Error reading wallets file: %v", err)
	}

	// Define a struct to match the JSON structure
	type Wallet struct {
		Address string `json:"address"`
		Balance uint64 `json:"balance"`
	}

	var wallets []Wallet
	if err := json.Unmarshal(data, &wallets); err != nil {
		log.Fatalf("Error unmarshaling wallets: %v", err)
	}

	// Extract addresses and balances into separate arrays
	addresses := make([]string, len(wallets))
	balances := make([]uint64, len(wallets))

	for i, wallet := range wallets {
		addresses[i] = wallet.Address
		balances[i] = wallet.Balance
	}

	return addresses, balances

}
