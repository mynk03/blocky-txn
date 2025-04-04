package main

import (
	"blockchain-simulator/blockchain"
	"blockchain-simulator/execution_client"
	"blockchain-simulator/rpc"
	"blockchain-simulator/transaction"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
)

func main() {
	// Parse command line flags
	port := flag.String("port", "8080", "RPC server port")
	validatorAddr := flag.String("validator", "", "Validator address (required)")
	bootstrapAddr := flag.String("bootstrap", "", "Bootstrap peer address (optional)")
	flag.Parse()

	// Validate required flags
	if *validatorAddr == "" {
		fmt.Println("Error: validator address is required")
		flag.Usage()
		os.Exit(1)
	}

	// Create unique storage directory for this node
	storageDir := filepath.Join("ChainData", "node"+*port)
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}

	// Create transaction pool
	txPool := transaction.NewTransactionPool()

	// Create LevelDB storage with unique directory
	storage, err := blockchain.NewLevelDBStorage(storageDir)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer storage.Close()

	// Create blockchain
	chain := blockchain.NewBlockchain(
		storage,
		[]string{*validatorAddr},
		[]uint64{1000000}, // Initial balance for validator
	)

	// Create execution client
	client, err := execution_client.NewExecutionClient(
		txPool,
		chain,
		common.HexToAddress(*validatorAddr),
	)
	if err != nil {
		log.Fatalf("Failed to create execution client: %v", err)
	}

	// Log the node's address and peer ID
	log.Printf("Node address: %s", client.GetAddress())
	log.Printf("Peer ID: %s", client.GetPeerID())

	// Connect to bootstrap peer if provided
	if *bootstrapAddr != "" {
		if err := client.ConnectToPeer(*bootstrapAddr); err != nil {
			log.Printf("Warning: Failed to connect to bootstrap peer: %v", err)
		} else {
			log.Printf("Connected to bootstrap peer: %s", *bootstrapAddr)
		}
	}

	// Create and start RPC server
	server := rpc.NewServer(client)
	log.Printf("Starting RPC server on port %s", *port)
	if err := server.Start(*port); err != nil {
		log.Fatalf("Failed to start RPC server: %v", err)
	}
}
