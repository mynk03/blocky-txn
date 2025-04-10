package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"blockchain-simulator/transaction"
	"blockchain-simulator/wallet"

	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// WalletData represents a wallet with its private key and initial state
type WalletData struct {
	Wallet     wallet.MockWallet
	PrivateKey string `json:"privateKey"`
	Address    string `json:"address"`
	Balance    uint64 `json:"balance"`
	Nonce      uint64 `json:"nonce"`
}

// TransactionRequest represents a transaction request
type TransactionRequest struct {
	TransactionHash string `json:"transactionHash"`
	Sender          string `json:"sender"`
	Receiver        string `json:"receiver"`
	Amount          uint64 `json:"amount"`
	Nonce           uint64 `json:"nonce"`
	Timestamp       uint64 `json:"timestamp"`
	Signature       string `json:"signature"`
}

// get the environment variable
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {

	// Load .env file
	if err := godotenv.Load(); err != nil {
		logrus.Warn("No .env file found")
	}

	totalWallets := 5
	totalTransactions := 5

	// Create chain_data/genesis_data directory if it doesn't exist
	if err := os.MkdirAll("chain_data/genesis_data", 0755); err != nil {
		logrus.Errorf("Error creating wallet directory: %v\n", err)
		return
	}

	fmt.Print("\nLoading the environment variables .... ")
	// get the wallets path from the environment variable
	walletsPath := getEnv("WALLETS_PATH", "chain_data/genesis_data/mock_wallets.json")
	transactionsPath := getEnv("TRANSACTIONS_PATH", "chain_data/genesis_data/mock_transactions.json")

	// create the json file for wallets and transactions directories if they don't exist
	createJsonFile(walletsPath)
	createJsonFile(transactionsPath)

	// create wallets and store them in a json file
	wallets := createAndStoreWallets(totalWallets, walletsPath)

	// read wallets from a json file
	walletsFromJSON := readWallets(walletsPath)

	// create transactions and store them in a json file
	transactions := createTransactions(wallets, walletsFromJSON, totalTransactions)

	// store transactions in a json file
	storeTransactions(transactions, transactionsPath)
}

// create wallets and store them in a json file
func createAndStoreWallets(totalWallets int, walletsPath string) []WalletData {
	fmt.Print("Creating wallets...")
	// Generate totalWallets wallets
	wallets := make([]WalletData, totalWallets)
	for i := 0; i < totalWallets; i++ {
		wallet, err := wallet.NewMockWallet()
		if err != nil {
			fmt.Printf("Error creating wallet %d: %v\n", i+1, err)
			return nil
		}

		wallets[i] = WalletData{
			Wallet:     *wallet,
			PrivateKey: hex.EncodeToString(wallet.GetPrivateKey().D.Bytes()),
			Address:    wallet.GetAddress().Hex(),
			Nonce:      0,
			Balance:    100,
		}
	}

	// Save wallets to JSON file
	walletsJSON, err := json.MarshalIndent(wallets, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling wallets: %v\n", err)
		return nil
	}

	if err := os.WriteFile(walletsPath, walletsJSON, 0644); err != nil {
		fmt.Printf("Error saving wallets: %v\n", err)
		return nil
	}

	fmt.Println("Wallets saved in ", walletsPath)
	return wallets
}

// read wallets from a json file
func readWallets(walletsPath string) []WalletData {
	fmt.Println("Reading wallets from a json file ...")
	wallets := make([]WalletData, 0)

	walletsJSON, err := os.ReadFile(walletsPath)
	if err != nil {
		fmt.Printf("Error reading wallets: %v\n", err)
		return nil
	}

	err = json.Unmarshal(walletsJSON, &wallets)
	if err != nil {
		fmt.Printf("Error unmarshalling wallets: %v\n", err)
		return nil
	}

	return wallets
}

// create transactions and store them in a json file
func createTransactions(wallets []WalletData, walletsFromJSON []WalletData, totalTransactions int) []TransactionRequest {
	fmt.Println("Creating transactions ...")
	totalWallets := len(walletsFromJSON)
	// Generate transactions
	transactions := make([]TransactionRequest, totalTransactions)
	for i := 0; i < totalTransactions; i++ {
		sender := wallets[i]
		receiver := wallets[(i+1)%totalWallets] // Send to next wallet, wrapping around

		// Create a transaction object for hash generation
		tx := transaction.Transaction{
			Sender:    common.HexToAddress(sender.Wallet.GetAddress().Hex()),
			Receiver:  common.HexToAddress(receiver.Wallet.GetAddress().Hex()),
			Amount:    10,
			Nonce:     sender.Nonce,
			Timestamp: uint64(time.Now().Unix()),
		}

		// Generate transaction hash using the GenerateHash method
		txHash := tx.GenerateHash()
		tx.TransactionHash = txHash

		// Sign the transaction
		signature, err := sender.Wallet.SignTransaction(common.HexToHash(txHash))
		if err != nil {
			fmt.Printf("Error signing transaction: %v\n", err)
			return nil
		}

		// add signature to the transaction
		tx.Signature = signature

		// Verify the transaction signature
		valid, err := tx.Verify()
		if err != nil {
			fmt.Printf("Error verifying transaction: %v\n", err)
			return nil
		}

		// Convert signature to hex string for JSON storage
		signatureHex := hex.EncodeToString(signature)

		// Create transaction request
		txRequest := TransactionRequest{
			TransactionHash: txHash,
			Sender:          sender.Wallet.GetAddress().Hex(),
			Receiver:        receiver.Wallet.GetAddress().Hex(),
			Amount:          10,
			Nonce:           sender.Nonce + 1,
			Timestamp:       uint64(time.Now().Unix()),
			Signature:       signatureHex,
		}

		// Verify the transaction signature

		if !valid {
			fmt.Printf("Invalid signature for transaction %d\n", i+1)
			return nil
		}

		transactions[i] = txRequest

		// Increment nonce for next transaction
		wallets[i].Nonce++
	}

	return transactions
}

// store transactions in a json file
func storeTransactions(transactions []TransactionRequest, transactionsPath string) {
	fmt.Println("Storing transactions in a json file ...")
	transactionsJSON, err := json.MarshalIndent(transactions, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling transactions: %v\n", err)
		return
	}

	os.WriteFile(transactionsPath, transactionsJSON, 0644)
	fmt.Println("Transactions stored in ", transactionsPath)
}

// create a json file
func createJsonFile(jsonFilePath string) {
	fmt.Println("Creating a json file ...")

	// Create the directory path if it doesn't exist
	dir := filepath.Dir(jsonFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Println("Failed to create directories:", err)
		return
	}

	// Create the file (truncates if exists, or creates if not)
	file, err := os.Create(jsonFilePath)
	if err != nil {
		fmt.Println("Failed to create file:", err)
		return
	}
	defer file.Close()
}
