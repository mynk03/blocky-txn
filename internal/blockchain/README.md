# Blockchain Package

This package implements a simplified blockchain system with persistent storage using LevelDB. It provides core blockchain functionality including block management, state management, and transaction handling.

## Overview

The blockchain package consists of several key components:

- **Blockchain**: Core blockchain implementation with block management
- **Storage**: Persistent storage interface and LevelDB implementation
- **State Management**: State trie for account management
- **Block**: Block structure and operations
- **Genesis**: Genesis block creation and initialization

## Key Components

### 1. Blockchain (`blockchain.go`)

The main blockchain implementation that manages:
- Block chain storage and retrieval
- State management
- Validator management
- Block addition and validation

Key functions:
- `NewBlockchain`: Creates a new blockchain with initial accounts
- `AddBlock`: Adds a validated block to the chain
- `GetLatestBlock`: Retrieves the most recent block
- `GetBlockByHash`: Retrieves a block by its hash
- `GetBlockByIndex`: Retrieves a block by its index

### 2. Storage (`leveldb.go`, `storage.go`)

Implements persistent storage using LevelDB with the following features:
- Block storage and retrieval
- State trie storage
- Transaction management
- Pending transaction handling

Key storage operations:
- `PutBlock`: Stores a block
- `GetBlock`: Retrieves a block
- `PutState`: Stores state trie
- `GetState`: Retrieves state trie
- `PutTransaction`: Stores a transaction
- `GetTransaction`: Retrieves a transaction
- `GetPendingTransactions`: Retrieves pending transactions

### 3. State Management (`state_root.go`)

Manages the state trie which tracks:
- Account balances
- Account states
- State transitions

### 4. Block Structure (`block.go`)

Defines the block structure with:
- Block index
- Previous block hash
- State root
- Transactions
- Validator information
- Timestamp

### 5. Genesis Block (`genesis.go`)

Handles the creation and initialization of the genesis block:
- Initial account funding
- State trie initialization
- Validator setup

## Data Storage

The package uses LevelDB for persistent storage with the following key prefixes:
- `b:` - Block data
- `s:` - State trie data
- `a:` - Account data
- `tx:` - Transaction data
- `pendingTx:` - Pending transactions

## Usage Example

```go
// Initialize storage
storage, err := blockchain.NewLevelDBStorage("./chaindata")
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

// Create initial accounts and balances
accounts := []string{"0x123...", "0x456..."}
balances := []uint64{1000, 2000}

// Initialize blockchain
chain := blockchain.NewBlockchain(storage, accounts, balances)

// Add a new block
newBlock := Block{
    Index:        1,
    PreviousHash: chain.GetLatestBlockHash(),
    // ... other block fields
}

success, err := chain.AddBlock(newBlock)
if err != nil {
    log.Fatal(err)
}
```

## Testing

The package includes comprehensive tests:
- `blockchain_test.go`: Blockchain functionality tests
- `leveldb_test.go`: Storage implementation tests
- `state_root_test.go`: State management tests

## Dependencies

- `github.com/syndtr/goleveldb/leveldb`: LevelDB implementation
- `github.com/ethereum/go-ethereum/common`: Ethereum common utilities
- `github.com/sirupsen/logrus`: Logging

## License
This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details. The MIT License is a permissive license that is short and to the point.