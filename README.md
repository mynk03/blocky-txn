# Blockchain Simulator

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)


## Overview
The Blockchain Simulator is a Go-based application designed to emulate core blockchain functionalities. It includes mining, transaction handling, and achieving consensus among nodes. This modular simulator provides a foundational platform for learning and prototyping blockchain concepts, with extensible features for advanced use cases.

## Features
- **Blockchain Layer**: Manages the creation, validation, and storage of blocks.
- **Transaction Layer**: Handles the creation, signing, and validation of transactions.
- **Consensus Layer**: Implements pluggable consensus mechanisms: 
  - **Practical Byzantine Fault Tolerance (pBFT)**: Ensures fast and consistent consensus in permissioned environments.
  - **Proof of Stake (PoS)**: Selects validators based on their stake in the network.
- **State Layer**: Maintains the global state of accounts and balances using a Merkle Patricia Trie.
- **Network Layer**: Simulates a peer-to-peer (P2P) network with latency and message loss.
- **Command-Line Interface (CLI)**: Provides user-friendly commands to interact with the blockchain.

## Technical Stack
- **Language**: Go
- **Libraries**:
  - `crypto` for hashing and digital signatures
  - `net` for network communication
  - `sync` for concurrency control
- **Pluggable Consensus**:
  - pBFT for quick consensus in private blockchains.
  - PoS for decentralized validator selection.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone git@github.com/ANCILAR/blockchain-simulator.git
   cd blockchain-simulator
   ```

2. **Install Dependencies**:
   Ensure Go is installed on your system. For Go installation, refer to [Go's official site](https://golang.org/dl/).
   ```bash
   go mod tidy
   ```


## Usage

### Quick Start Guide

1. **Generate Initial Wallets and Transactions**
   ```bash
   # First, update the number of wallets and transactions in .env
   echo "TOTAL_WALLETS=5" >> .env
   echo "TOTAL_TRANSACTIONS=10" >> .env
   
   # Generate wallets and transactions
   go run internal/wallet/cmd/main.go
   
   # Verify the generated files
   cat chain_data/genesis_data/initial_users/mock_wallets.json
   cat chain_data/genesis_data/initial_users/mock_transactions.json
   ```

2. **Configure Node Environment**
   ```bash
   # Copy the example environment file
   cp .env.example .env
   
   # Update the environment variables for Node 1
   echo "VALIDATOR_PRIVATE_KEY=<private_key_from_wallets_cmd>" >> .env
   echo "DATA_DIR=\"./chain_data/node1\"" >> .env
   echo "HTTP_PORT=8081" >> .env
   echo "HARBOR_PORT=50051" >> .env
   
   # For Node 2 (in a separate terminal)
   echo "VALIDATOR_PRIVATE_KEY=<different_private_key_from_wallets_cmd>" >> .env
   echo "DATA_DIR=\"./chain_data/node2\"" >> .env
   echo "HTTP_PORT=8082" >> .env
   echo "HARBOR_PORT=50052" >> .env
   ```

3. **Start the Nodes**
   ```bash
   # Start Node 1
   make start-separate
   
   # In a new terminal, start Node 2
   make start-separate
   ```

4. **Connect the Nodes**
   - If nodes are not connected.
   ```bash
   # Make the connection script executable
   chmod +x scripts/connect_peers.sh
   
   # Run the connection script
   ./scripts/connect_peers.sh
   ```

5. **Test Transactions**
   ```bash
   # Make the test script executable
   chmod +x scripts/test_transaction.sh
   
   # Run the test script
   ./scripts/test_transaction.sh
   ```

### Detailed Steps

1. **Wallet Generation**
   - The wallet package generates mock wallets and transactions
   - Wallets are stored in `chain_data/genesis_data/initial_users/mock_wallets.json`
   - Transactions are stored in `chain_data/genesis_data/initial_users/mock_transactions.json`
   - Each wallet has a private key, address, and initial balance

2. **Node Configuration**
   - Each node requires:
     - A unique validator private key from the generated wallets
     - A separate data directory
     - Unique HTTP and Harbor ports
     - Network configuration (listen address, etc.)

3. **Node Operation**
   - Nodes communicate via libp2p for P2P networking
   - Use GossipSub protocol for message propagation
   - Implement mDNS for local peer discovery
   - Provide HTTP API for user interactions
   - Harbor RPC for consensus communication

4. **Transaction Testing**
   - The test script will:
     - Send a test transaction to Node 1
     - Wait for transaction broadcast
     - Check transaction pools on both nodes
     - Verify peer connections
     - Display all transactions in both nodes' pools

### Environment Variables

Key environment variables for node configuration:

```bash
# Network Configuration
LISTEN_ADDR=/ip4/127.0.0.1/tcp/0
INITIAL_BALANCE=5000
LOG_LEVEL=debug

# Node Configuration
VALIDATOR_PRIVATE_KEY=<private_key>
DATA_DIR="./chain_data/node1"
HTTP_PORT=8081
HARBOR_PORT=50051

# Wallet Configuration
TOTAL_WALLETS=5
WALLETS_PATH="chain_data/genesis_data/initial_users/mock_wallets.json"
TRANSACTIONS_PATH="chain_data/genesis_data/initial_users/mock_transactions.json"
```

### HTTP API Usage

1. **Submit a Transaction**
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

2. **Get Pending Transactions**
   ```bash
   curl http://localhost:8081/txn/pool/transactions
   ```

3. **Get Node Information**
   ```bash
   curl http://localhost:8081/node/id
   curl http://localhost:8081/test/peers
   ```

For more detailed information about the consensus client, execution client, and wallet package, refer to their respective README files in the `internal` directory.

## Architecture

![blockchain-simulator](https://github.com/user-attachments/assets/a03f08f3-d52d-41e2-a31c-19406341706d)

### Layers
1. **Blockchain Layer**:
   - Stores and validates blocks.
   - Maintains chain integrity by linking blocks through hashes.

2. **Transaction Layer**:
   - Validates and pools transactions until included in a block.
   - Uses account-based model with balances and nonces.

3. **Consensus Layer**:
   - **pBFT**:
     - Operates in three phases: Pre-prepare, Prepare, and Commit.
     - Requires a quorum of nodes to agree on the block.
     - Suitable for permissioned networks.
   - **PoS**:
     - Selects block validators based on the amount of tokens staked.
     - Validators receive transaction fees and rewards.
   - Consensus mechanism is configurable via `config.yaml`.

4. **State Layer**:
   - Uses a Merkle Patricia Trie to store account balances and state data.
   - Updates state after processing transactions in each block.

5. **Network Layer**:
   - Simulates P2P communication with configurable latency and packet loss.

6. **CLI Layer**:
   - Enables interaction with the blockchain through a command-line interface.

**For detailed architecture**, see [Architecture Documentation](https://www.notion.so/Blockchain-Simulator-Architecture-Detailed-Layer-by-Layer-Explanation-1a75a32c345980bc90cdf49e4945a5ba?showMoveTo=true&saveParent=true)
## Configuration

### config.yaml
Customize settings for the simulator:
```yaml
blockchain:
  genesis_block:
    initial_balances:
      "address1": 1000
      "address2": 500

consensus:
  type: "pBFT"  # Options: "pBFT", "PoS"
  pBFT:
    quorum: 2/3  # Fraction of nodes required to agree
  PoS:
    reward: 5    # Reward per block in tokens

network:
  latency: 100ms  # Simulated network latency
  packet_loss: 0.01  # Simulated packet loss rate

mining:
  difficulty: 4  # Only for PoW (if added later)
```

## Development

### Adding Consensus Mechanisms
- Implement the `Consensus` interface for new algorithms:
  ```go
  type Consensus interface {
      SelectValidator() string
      ValidateBlock(block Block) bool
      CreateBlock(transactions []Transaction) Block
  }
  ```
- Add the new mechanism to the consensus factory.

### Testing
- Run unit tests:
  ```bash
  go test ./...
  ```
- Simulate various scenarios:
  - High transaction volumes.
  - Network partitions.

## Future Enhancements
- Add new consensus algorithms (e.g., PoA, DPoS).
- Implement block explorers for visualization.
- Support smart contracts.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. The MIT License is a permissive license that is short and to the point.
