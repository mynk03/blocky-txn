# Transaction Package

The transaction package provides core functionality for managing blockchain transactions, including transaction creation, validation, and pool management. It implements secure transaction handling with cryptographic signature verification and state validation.

## Overview

The transaction package consists of two main components:
- **Transaction**: Core transaction structure and validation
- **TransactionPool**: In-memory pool for pending transactions

## Key Components

### 1. Transaction (`transaction.go`)

The Transaction structure represents a blockchain transaction with:
- Sender and receiver addresses
- Amount and nonce
- Transaction status (Success, Pending, Failed)
- Cryptographic signature
- Block number and timestamp

Key functions:
- `GenerateHash()`: Creates a unique transaction hash
- `Verify()`: Validates the transaction signature
- `ValidateWithState()`: Validates transaction against current state

### 2. TransactionPool (`transaction_pool.go`)

The TransactionPool manages pending transactions with:
- Thread-safe transaction storage
- Duplicate prevention
- Bulk transaction operations
- Transaction status tracking

Key functions:
- `AddTransaction()`: Adds a transaction to the pool
- `GetTransaction()`: Retrieves a transaction by hash
- `RemoveTransaction()`: Removes a transaction from the pool
- `GetAllTransactions()`: Returns all transactions in the pool
- `RemoveBulkTransactions()`: Removes multiple transactions

## Implementation Details

### Transaction Validation

Transactions are validated through multiple checks:
1. **Signature Verification**
   - ECDSA signature validation
   - Sender address recovery
   - Signature format verification

2. **State Validation**
   - Sender account existence
   - Sufficient balance check
   - Nonce validation
   - Address format validation

### Transaction Pool Management

The transaction pool provides:
- Thread-safe operations using mutex
- Efficient transaction lookup
- Bulk transaction operations
- Status tracking

## Usage Example

```go
// Create a new transaction
tx := transaction.Transaction{
    Sender:    common.HexToAddress("0x123..."),
    Receiver:  common.HexToAddress("0x456..."),
    Amount:    1000,
    Nonce:     1,
    Timestamp: time.Now().Unix(),
}

// Generate transaction hash
tx.TransactionHash = tx.GenerateHash()

// Sign the transaction
privateKey, _ := crypto.HexToECDSA("private_key_hex")
hash := common.HexToHash(tx.TransactionHash)
signature, _ := crypto.Sign(hash.Bytes(), privateKey)
tx.Signature = signature

// Create transaction pool
pool := transaction.NewTransactionPool()

// Add transaction to pool
err := pool.AddTransaction(tx)
if err != nil {
    log.Fatal(err)
}

// Get all pending transactions
pendingTxs := pool.GetAllTransactions()
```

## Testing

The package includes comprehensive tests:
- `transaction_test.go`: Transaction validation tests
- `transaction_pool_test.go`: Pool management tests
- `transaction_pool_test.go`: Pool operations tests

## Error Handling

The package defines several error types:
- `ErrInvalidSender`: Invalid sender address
- `ErrInvalidRecipient`: Invalid recipient address
- `ErrInvalidAmount`: Invalid transaction amount
- `ErrInvalidNonce`: Invalid transaction nonce
- `ErrInsufficientFunds`: Insufficient sender balance
- `ErrInvalidSignature`: Invalid transaction signature
- `ErrDuplicateTransaction`: Duplicate transaction in pool

## Security Considerations

1. **Transaction Security**
   - ECDSA signature verification
   - Nonce-based replay protection
   - Balance validation
   - Address format validation

2. **Pool Security**
   - Thread-safe operations
   - Duplicate prevention
   - Atomic bulk operations

## Performance Considerations

1. **Transaction Validation**
   - Efficient hash generation
   - Optimized signature verification
   - Minimal state lookups

2. **Pool Operations**
   - O(1) transaction lookup
   - Efficient bulk operations
   - Minimal locking overhead

## Dependencies

- `github.com/ethereum/go-ethereum/common`: Ethereum utilities
- `github.com/ethereum/go-ethereum/crypto`: Cryptographic functions
- `github.com/sirupsen/logrus`: Logging

## License
This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details. The MIT License is a permissive license that is short and to the point.