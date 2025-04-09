package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"blockchain-simulator/wallet"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// WalletData represents a wallet with its private key and initial state
type WalletData struct {
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

func main() {
	// Create wallets directory if it doesn't exist
	if err := os.MkdirAll("initial_users", 0755); err != nil {
		fmt.Printf("Error creating wallet directory: %v\n", err)
		return
	}

	// Generate 20 wallets
	wallets := make([]WalletData, 20)
	for i := 0; i < 20; i++ {
		wallet, err := wallet.NewMockWallet()
		if err != nil {
			fmt.Printf("Error creating wallet %d: %v\n", i+1, err)
			return
		}

		privateKeyBytes := crypto.FromECDSA(wallet.GetPrivateKey())
		wallets[i] = WalletData{
			PrivateKey: common.Bytes2Hex(privateKeyBytes),
			Address:    wallet.GetAddress().Hex(),
			Balance:    10000, // Initial balance
			Nonce:      0,   // Initial nonce
		}
	}

	// Save wallets to JSON file
	walletsJSON, err := json.MarshalIndent(wallets, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling wallets: %v\n", err)
		return
	}

	if err := os.WriteFile("initial_users/mock_wallets.json", walletsJSON, 0644); err != nil {
		fmt.Printf("Error saving wallets: %v\n", err)
		return
	}

	// Generate transactions
	transactions := make([]TransactionRequest, 20)
	for i := 0; i < 20; i++ {
		sender := wallets[i]
		receiver := wallets[(i+1)%20] // Send to next wallet, wrapping around

		// Create transaction data
		txData := map[string]interface{}{
			"sender":    sender.Address,
			"receiver":  receiver.Address,
			"amount":    10, // Fixed amount for testing
			"nonce":     sender.Nonce,
			"timestamp": uint64(time.Now().Unix()),
		}

		// Marshal transaction data
		txDataBytes, err := json.Marshal(txData)
		if err != nil {
			fmt.Printf("Error marshaling transaction data: %v\n", err)
			return
		}

		// Hash the transaction data
		txHash := crypto.Keccak256Hash(txDataBytes)

		// Sign the transaction
		wallet, err := wallet.NewMockWallet()
		if err != nil {
			fmt.Printf("Error creating wallet for signing: %v\n", err)
			return
		}
		signature, err := wallet.SignTransaction(txHash)
		if err != nil {
			fmt.Printf("Error signing transaction: %v\n", err)
			return
		}

		// Create transaction request
		transactions[i] = TransactionRequest{
			TransactionHash: txHash.Hex(),
			Sender:          sender.Address,
			Receiver:        receiver.Address,
			Amount:          10,
			Nonce:           sender.Nonce+1,
			Timestamp:       uint64(time.Now().Unix()),
			Signature:       common.Bytes2Hex(signature),
		}

		// Increment nonce for next transaction
		wallets[i].Nonce++
	}

	// Save transactions to JSON file
	transactionsJSON, err := json.MarshalIndent(transactions, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling transactions: %v\n", err)
		return
	}

	if err := os.WriteFile("initial_users/mock_transactions.json", transactionsJSON, 0644); err != nil {
		fmt.Printf("Error saving transactions: %v\n", err)
		return
	}

	fmt.Println("Successfully generated 20 wallets and transactions!")
	fmt.Println("Wallets saved to: initial_users/mock_wallets.json")
	fmt.Println("Transactions saved to: initial_users/mock_transactions.json")
}
