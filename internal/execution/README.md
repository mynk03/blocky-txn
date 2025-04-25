# Execution Client

The execution client is a key component of the blockchain simulator that handles transaction processing, block creation, and peer-to-peer communication using libp2p.

## Features

- P2P network communication using libp2p with GossipSub protocol
- Transaction pool management with validation
- Block creation and validation through Harbor RPC
- HTTP API for user interactions
- Harbor RPC server for consensus client communication
- Validator key management
- Dynamic port allocation
- mDNS-based peer discovery

## Quick Start

1. First, initialize the wallets to get initial user addresses and funds:
```bash
go run wallet/cmd/main.go
```
This will generate initial wallets and their private keys. Make sure to save these private keys as you'll need them to start nodes.

2. Verify the generated JSON files:
```bash
# Check the generated wallets
cat chain_data/genesis_data/initial_users/mock_wallets.json

# Check the generated transactions
cat chain_data/genesis_data/initial_users/mock_transactions.json
```
Make sure these files contain valid JSON data with wallet addresses and initial transactions.

3. Copy the environment file and update the values:
```bash
cp .env.example .env
```

4. Edit the `.env` file with your configuration:
```bash
# Node 1 Configuration
VALIDATOR_PRIVATE_KEY=<private_key_from_wallets_cmd>
DATA_DIR="./chain_data/node1"
HTTP_PORT=8081
HARBOR_PORT=50051

# Node 2 Configuration (uncomment and update for second node)
# VALIDATOR_PRIVATE_KEY=<private_key_from_wallets_cmd>
# DATA_DIR="./chain_data/node2"
# HTTP_PORT=8082
# HARBOR_PORT=50052
```

5. Run the node:
```bash
go run execution_client/cmd/main.go
```

## HTTP API Documentation

### Transaction Management

#### Submit a Transaction
```bash
curl -X POST http://localhost:8081/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "transactionHash": "32d81664f96af65c6266726c439019fd2c88272bd23065f1b946e1baf480c147",
    "sender": "0xfb5865ee63A8D3C5c69F76f181275ef36d92BddA",
    "receiver": "0x24E82C112D9B97c49890DAC46BCCD32768428c16",
    "amount": 10,
    "nonce": 1,
    "timestamp": 1744294774,
    "signature": "8df23503cc58894e71057f3fbd48fc6f0a5cc34595a136140cea95bb5f3cc26f3a5a40cebfdf048f8a88d4bac3be1131cb2b52e8794cdddd22c7df3d8cda516500"
  }'
```

#### Get Pending Transactions
```bash
curl http://localhost:8081/txn/pool/transactions
```

### Node Information

#### Get Node ID
```bash
curl http://localhost:8081/node/id
```

#### List Connected Peers
```bash
curl http://localhost:8081/test/peers
```

#### Connect to a Peer
```bash
curl -X POST http://localhost:8081/test/peer/connect \
  -H "Content-Type: application/json" \
  -d '{"peerID": "/ip4/127.0.0.1/tcp/58096/p2p/12D3KooWHtkcAnYeqdXvoAZeTAjqzsqbBX9KU2eNSDWwoH7WyFfB"}'
```

## Running Multiple Nodes

To run multiple nodes on your local machine, you need to specify different ports and data directories for each node in the `.env`. Here's how to run two nodes:

```bash
go run execution_client/cmd/main.go           
```

- Make sure to be in root folder i.e. `blockchain-simulator`
- Use different private keys from the wallets command for each node
- Configure different ports in the `.env` file for each node

### Quick Peer Connection

To quickly connect peers between nodes, you can use the connection script:

1. Make the connection script executable:

**Give executable permission**  
```bash
chmod +x execution_client/scripts/test_transaction.sh
```

**Run the test script:**
```bash
./execution_client/scripts/connect_peers.sh   
```

## Testing

### Running Test Scripts

The repository includes test scripts to help you test the functionality:

1. Make the test script executable:
```bash
chmod +x execution_client/scripts/test_transaction.sh
```

2. Run the test script:
```bash
./execution_client/scripts/test_transaction.sh
```

This script will:
- Send a test transaction to Node 1
- Wait for transaction broadcast
- Check transaction pools on both nodes
- Verify peer connections
- Display all transactions in both nodes' pools

## Architecture

### Components

1. **Execution Client**
   - Manages P2P network using libp2p
   - Handles transaction broadcasting
   - Implements GossipSub protocol
   - Manages peer discovery via mDNS

2. **Transaction Pool**
   - In-memory storage of pending transactions
   - Transaction validation
   - Prevents double-spending
   - Transaction status tracking

3. **Harbor Server**
   - gRPC server for consensus communication
   - Block creation and validation
   - State trie management
   - Transaction processing

4. **HTTP Server**
   - REST API for user interactions
   - Transaction submission
   - Node information retrieval
   - Peer management

### Network Protocol

- Uses libp2p for P2P networking
- Implements GossipSub for message propagation
- mDNS for local peer discovery
- gRPC for consensus communication
- HTTP for user interactions

## Environment Variables

`.env`
```
LISTEN_ADDR=/ip4/127.0.0.1/tcp/0
INITIAL_BALANCE=5000
LOG_LEVEL=debug

WALLETS_PATH="chain_data/genesis_data/initial_users/mock_wallets.json"
TRANSACTIONS_PATH="chain_data/genesis_data/initial_users/mock_transactions.json"

# Node 1 Configuration
VALIDATOR_PRIVATE_KEY=<private_key>
DATA_DIR="./chain_data/node1"
HTTP_PORT=8081
HARBOR_PORT=50051

# Node 2 Configuration
# VALIDATOR_PRIVATE_KEY=<private_key>
# DATA_DIR="./chain_data/node2"
# HTTP_PORT=8082
# HARBOR_PORT=50052

# Description of each variable:
# VALIDATOR_PRIVATE_KEY: Private key in hex format (without 0x prefix)
# DATA_DIR: Directory for storing blockchain data
# HTTP_PORT: Port for HTTP API server
# HARBOR_PORT: Port for Harbor RPC server
# LISTEN_ADDR: P2P network listen address
# INITIAL_BALANCE: Initial balance for validator account
# LOG_LEVEL: Logging level (debug, info, warn, error)
```

## Logging

The node provides detailed logging at different levels:
- DEBUG: Detailed operational information
- INFO: General operational information
- WARN: Warning messages
- ERROR: Error conditions

## Shutdown

The node can be gracefully shut down using:
- Ctrl+C (SIGINT)
- SIGTERM signal

All components will be properly closed and data will be persisted.

## Dependencies

- `github.com/libp2p/go-libp2p`: P2P networking
- `github.com/libp2p/go-libp2p-pubsub`: GossipSub protocol
- `google.golang.org/grpc`: gRPC server
- `github.com/gin-gonic/gin`: HTTP server
- `github.com/ethereum/go-ethereum/common`: Ethereum utilities
- `github.com/sirupsen/logrus`: Logging

## License
This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details. The MIT License is a permissive license that is short and to the point.