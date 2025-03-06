# Blockchain Simulator

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

3. **Build the Project**:
   ```bash
   go build -o blockchain-simulator
   ```

4. **Run the Simulator**:
   ```bash
   ./blockchain-simulator
   ```

## Usage

### CLI Commands
- **Initialize a Blockchain**:
  ```bash
  ./blockchain-simulator createblockchain
  ```
- **Send a Transaction**:
  ```bash
  ./blockchain-simulator send --from <address> --to <address> --amount <value>
  ```
- **View Blockchain**:
  ```bash
  ./blockchain-simulator viewchain
  ```
- **Add a Node**:
  ```bash
  ./blockchain-simulator addnode --address <node-address>
  ```
- **Check Balance**:
  ```bash
  ./blockchain-simulator balance --address <address>
  ```

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
This project is licensed under the MIT License. See the LICENSE file for details.
