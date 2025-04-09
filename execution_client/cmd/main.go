package main

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/execution_client"
	"blockchain-simulator/transaction"
	"crypto/ecdsa"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

var (
	// CLI flags
	listenAddr     = flag.String("listen", "/ip4/127.0.0.1/tcp/0", "Listen address for libp2p host")
	dataDir        = flag.String("datadir", "./data", "Data directory for blockchain storage")
	httpPort       = flag.String("http-port", "8080", "HTTP server port")
	harborPort     = flag.String("harbor-port", "50051", "Harbor RPC server port")
	validatorKey   = flag.String("validator-key", "", "Validator private key (hex)")
	initialBalance = flag.Uint64("initial-balance", 1000, "Initial balance for validator account")
	logLevel       = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	// Setup logger
	logger := setupLogger(*logLevel)
	logger.Info("Starting execution client node...")

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		logger.Fatalf("Failed to create data directory: %v", err)
	}

	// load private key from env variables if validatorKey is not passed as a flag
	if *validatorKey == "" {
		// Load .env file
		if err := godotenv.Load(); err != nil {
			logrus.Warn("No .env file found")
		}
		logger.Info("Validator private key is not set, using env variables")
		*validatorKey = os.Getenv("VALIDATOR_PRIVATE_KEY")
		logger.Infof("Validator private key: %s", *validatorKey)
		if *validatorKey == "" {
			logger.Fatalf("Validator private key is not set")
		}
	}

	// using ECDSA private key to generate validator address
	privateKey, err := crypto.HexToECDSA(*validatorKey)
	if err != nil {
		logger.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	validatorAddr := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Initialize blockchain storage
	storage, err := blockchain.NewLevelDBStorage(filepath.Join(*dataDir, "blockchain"))
	if err != nil {
		logger.Fatalf("Failed to create blockchain storage: %v", err)
	}
	defer storage.Close()

	// Create blockchain with initial validator account
	chain := blockchain.NewBlockchain(storage, []string{validatorAddr.Hex()}, []uint64{*initialBalance})

	// Create transaction pool
	txPool := transaction.NewTransactionPool()

	// Create Harbor server
	harborServer := execution_client.NewHarborServer(txPool, chain, logger)

	// Create execution client
	client, err := execution_client.NewExecutionClient(
		*listenAddr,
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
	if err := client.Start(*harborPort, httpServer, *httpPort); err != nil {
		logger.Fatalf("Failed to start execution client: %v", err)
	}

	// Print node information
	logger.Infof("Node started successfully")
	logger.Infof("HTTP server listening on :%s", *httpPort)
	logger.Infof("Harbor RPC server listening on :%s", *harborPort)
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
