# Wallet Package

The wallet package provides functionality for creating and managing mock wallets and transactions for testing purposes. It includes tools for generating wallets, creating transactions, and managing their state.

## Overview

The wallet package consists of:
- **MockWallet**: Mock wallet implementation for testing
- **Wallet Generator**: Command-line tool for creating wallets and transactions
- **Transaction Generator**: Tool for creating test transactions between wallets

## Features

- Generate mock wallets with private/public key pairs
- Create test transactions between wallets
- Store wallet and transaction data in JSON format
- Configurable number of wallets and transactions
- Environment-based configuration

## Quick Start

1. **Configuration**
Create a `.env` file in your project root:
```bash
# Number of wallets to generate
TOTAL_WALLETS=5

# Number of transactions to generate
TOTAL_TRANSACTIONS=5

# Paths for storing wallet and transaction data
WALLETS_PATH="chain_data/genesis_data/mock_wallets.json"
TRANSACTIONS_PATH="chain_data/genesis_data/mock_transactions.json"
```

2. **Generate Wallets and Transactions**
```bash
go run wallet/cmd/main.go
```

## Environment Variables

### Wallet Configuration
- `TOTAL_WALLETS`: Number of wallets to generate (default: 5)
- `WALLETS_PATH`: Path to store wallet data (default: "chain_data/genesis_data/mock_wallets.json")

### Transaction Configuration
- `TOTAL_TRANSACTIONS`: Number of transactions to generate (default: 5)
- `TRANSACTIONS_PATH`: Path to store transaction data (default: "chain_data/genesis_data/mock_transactions.json")

## Generated Files

### Wallet Data (mock_wallets.json)
```json
[
  {
    "privateKey": "hex_encoded_private_key",
    "address": "0x...",
    "balance": 100,
    "nonce": 0
  }
]
```

### Transaction Data (mock_transactions.json)
```json
[
  {
    "transactionHash": "hash",
    "sender": "0x...",
    "receiver": "0x...",
    "amount": 10,
    "nonce": 1,
    "timestamp": 1234567890,
    "signature": "hex_encoded_signature"
  }
]
```

## Usage Example

### Creating a Wallet
```go
// Create a new mock wallet
wallet, err := wallet.NewMockWallet()
if err != nil {
    log.Fatal(err)
}

// Get wallet address
address := wallet.GetAddress()

// Get private key
privateKey := wallet.GetPrivateKey()
```

### Signing a Transaction
```go
// Create transaction hash
hash := common.HexToHash("transaction_hash")

// Sign transaction
signature, err := wallet.SignTransaction(hash)
if err != nil {
    log.Fatal(err)
}
```

## Testing

The package includes comprehensive tests:
- `wallet_test.go`: Wallet functionality tests
- Transaction validation tests
- Signature verification tests

## Security Considerations

1. **Private Key Management**
   - Private keys are stored in memory only
   - Keys are generated using secure cryptographic functions
   - No persistent storage of private keys

2. **Transaction Security**
   - All transactions are signed using ECDSA
   - Nonce-based replay protection
   - Timestamp validation

## Performance Considerations

1. **Wallet Generation**
   - Efficient key pair generation
   - Minimal memory usage
   - Fast address derivation

2. **Transaction Processing**
   - Optimized signature generation
   - Efficient hash calculation
   - Minimal state overhead

## Dependencies

- `github.com/ethereum/go-ethereum/crypto`: Cryptographic functions
- `github.com/ethereum/go-ethereum/common`: Ethereum utilities
- `github.com/joho/godotenv`: Environment variable management
- `github.com/sirupsen/logrus`: Logging

## License
This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details. The MIT License is a permissive license that is short and to the point.