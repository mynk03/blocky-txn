# Execution Client

The execution client is a key component of the blockchain simulator that handles transaction processing, block creation, and peer-to-peer communication.

## Features

- P2P network communication using libp2p
- Transaction pool management
- Block creation and validation
- HTTP API for user interactions
- Harbor RPC server for consensus client communication
- Validator key management
- Dynamic port allocation

## Running Multiple Nodes

To run multiple nodes on your local machine, you need to specify different ports and data directories for each node. Here's how to run two nodes:

### Node 1
```bash
go run cmd/main.go \
  -listen "/ip4/0.0.0.0/tcp/0" \
  -http-port 8081 \
  -harbor-port 50051 \
  -initial-balance 5000 \
  -log-level debug \
  -validator-key dd3207e786abd81ae49ce81b8323610adf425cc7c175abe42a1190e413d6d04d \
  -datadir ./data1
```

### Node 2
```bash
go run cmd/main.go \
  -listen "/ip4/0.0.0.0/tcp/0" \
  -http-port 8082 \
  -harbor-port 50052 \
  -initial-balance 5000 \
  -log-level debug \
  -validator-key bc832b10ee6cf21c4975be4fa21de44dd1c3527f14244e531c69d13fa5224571 \
  -datadir ./data2
```

## What Gets Initialized

When you start a node, the following components are initialized:

1. **Logger**
   - Configurable log level (debug, info, warn, error)
   - Timestamp and formatted output

2. **Data Directory**
   - Blockchain storage
   - Transaction pool data
   - Node configuration

3. **Validator**
   - Private key loaded from flag or environment
   - Public address derived from private key
   - Initial balance set for validator account

4. **Blockchain**
   - LevelDB storage initialized
   - Genesis block created with validator account
   - Initial state trie setup

5. **Transaction Pool**
   - In-memory pool for pending transactions
   - Transaction validation logic

6. **Harbor Server**
   - gRPC server for consensus client communication
   - Block creation and validation endpoints

7. **Execution Client**
   - libp2p host for P2P networking
   - Message handling goroutines
   - Peer discovery setup

8. **HTTP Server**
   - REST API endpoints:
     - POST /transaction - Add new transaction
     - GET /node/id - Get node ID
     - GET /transactions - Get pending transactions
     - GET /test/peers - List all peers
     - POST /test/peer/connect - Connect to a peer

## Environment Variables

You can also use environment variables instead of command-line flags:

```bash
export VALIDATOR_PRIVATE_KEY=your_private_key_here
export HTTP_PORT=8081
export HARBOR_PORT=50051
export INITIAL_BALANCE=5000
export LOG_LEVEL=debug
export DATA_DIR=./data1
```

## Connecting Nodes

After starting multiple nodes, they will automatically discover each other through mDNS. You can also manually connect nodes using the HTTP API:

```bash
# First, get the peer ID of node1
curl http://localhost:8081/node/id

# Then use that peer ID to connect node2 to node1
curl -X POST http://localhost:8082/test/peer/connect \
  -H "Content-Type: application/json" \
  -d '{"Address": "/ip4/127.0.0.1/tcp/58096/p2p/12D3KooWHtkcAnYeqdXvoAZeTAjqzsqbBX9KU2eNSDWwoH7WyFfB"}'
```

## API Endpoints

### Transaction Management
- `POST /transaction` - Submit a new transaction
- `GET /transactions` - Get all pending transactions

### Node Information
- `GET /node/id` - Get node's P2P ID and address
- `GET /test/peers` - List all connected peers
- `POST /test/peer/connect` - Connect to a specific peer

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