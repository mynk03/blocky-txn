# Consensus Client

The Consensus Client is a core component of the blockchain simulator, responsible for managing peer-to-peer networking and consensus operations between blockchain nodes. It implements a robust communication layer using libp2p and provides an extensible interface for different consensus algorithms, with a default implementation of Proof of Stake (PoS).

## Overview

The Consensus Client connects blockchain nodes in a decentralized network and manages important consensus-related responsibilities including:

- Peer discovery and network communication
- Message broadcasting and receipt
- Validator selection for block production
- Slashing and punishment mechanisms for misbehaving validators
- Evidence handling for protocol violations
- Validator announcements and health monitoring

## Architecture

The consensus client is built on these key technologies:

- **libp2p**: Provides the p2p networking foundation, including peer discovery and messaging
- **GossipSub**: Implements the publish/subscribe messaging pattern for efficient message distribution
- **mDNS**: Handles local network peer discovery
- **Ethereum types**: Uses Ethereum-compatible addresses for validators

The primary components of the consensus client include:

1. **ConsensusClient**: The main struct that manages the p2p network and consensus operations
2. **ConsensusMessage**: The message format for communication between consensus nodes
3. **ConsensusAlgorithm interface**: An extensible interface that different consensus mechanisms can implement
4. **Proof of Stake implementation**: The default consensus algorithm  

## Features

### Messaging System

The client supports various message types for consensus operations:

- **BlockProposal**: Distributes new block proposals to the network
- **Vote**: Allows validators to vote on proposed blocks
- **ValidationMissed**: Reports validators that missed their validation duties
- **DoubleSignEvidence**: Reports validators that signed multiple blocks at the same height
- **InvalidBlockEvidence**: Reports validators that proposed invalid blocks
- **ValidatorAnnouncement**: Broadcasts validator status updates

### Validator Management

The client includes comprehensive validator management features:

- **Validator Registration**: Add new validators with staked tokens
- **Validator Selection**: Selects the next validator to produce a block
- **Slashing**: Punishes validators for rule violations
- **Offline Detection**: Identifies and reports validators that go offline
- **Validator Metrics**: Tracks performance statistics for each validator

### Network Management

The client provides several network-related features:

- **Automatic Peer Discovery**: Uses mDNS to find peers on the local network
- **Message Deduplication**: Prevents processing duplicate messages
- **Garbage Collection**: Periodically cleans up seen messages to prevent memory leaks
- **Direct Peer Connection**: Supports connecting to specific peers by address

## Usage

### Creating a Consensus Client

You can create a consensus client with either a predefined validator private key (recommended for production) or let the system generate a random address (useful for testing):

#### Option 1: Using a Private Key from Environment Variable

Set the `VALIDATOR_PRIVATE_KEY` environment variable with your hex-encoded private key before running your application:

```bash
# Linux/macOS
export VALIDATOR_PRIVATE_KEY=0xabc123...

# Windows
set VALIDATOR_PRIVATE_KEY=0xabc123...
```

Then create the client normally:

```go
// The client will use the private key from the environment variable
// to derive the validator address
client, err := NewConsensusClient("/ip4/127.0.0.1/tcp/9000", 200, nil)
if err != nil {
    log.Fatalf("Failed to create consensus client: %v", err)
}
```

#### Option 2: Using a Random Validator Address

If no `VALIDATOR_PRIVATE_KEY` environment variable is set, a random address will be generated:

```go
// Without a private key in the environment, a random address will be generated
client, err := NewConsensusClient("/ip4/127.0.0.1/tcp/9000", 200, nil)
if err != nil {
    log.Fatalf("Failed to create consensus client: %v", err)
}
```

#### Starting and Stopping the Client

```go
// Start the client (initializes pubsub, peer discovery, etc.)
err = client.Start()
if err != nil {
    log.Fatalf("Failed to start consensus client: %v", err)
}

// When done, stop the client to clean up resources
defer client.Stop()
```

### Proposing and Voting on Blocks

```go
// Propose a new block to the network
block := &blockchain.Block{
    Index:     blockHeight,
    Hash:      blockHash,
    PrevHash:  prevBlockHash,
    Timestamp: time.Now().Format(time.RFC3339),
    StateRoot: stateRoot,
    Validator: client.GetValidatorAddress().Hex(),
}
err = client.ProposeBlock(block)
if err != nil {
    log.Printf("Failed to propose block: %v", err)
}

// Submit a vote for a block
err = client.SubmitVote(blockHash, true) // true = approve, false = reject
if err != nil {
    log.Printf("Failed to submit vote: %v", err)
}
```

### Handling Incoming Messages

```go
// Get channels for incoming messages
proposalCh := client.GetProposalChannel()
voteCh := client.GetVoteChannel()
evidenceCh := client.GetEvidenceChannel()

// Process incoming block proposals
go func() {
    for block := range proposalCh {
        // Process the proposed block
        log.Printf("Received block proposal: %s", block.Hash)
    }
}()

// Process incoming votes
go func() {
    for vote := range voteCh {
        // Process the vote
        log.Printf("Received vote for block %s from %s (approve: %t)",
            vote.BlockHash, vote.Validator.Hex(), vote.Approve)
    }
}()

// Process incoming evidence
go func() {
    for evidence := range evidenceCh {
        // Process the evidence
        log.Printf("Received evidence against validator %s: %s",
            evidence.Validator.Hex(), evidence.Reason)
    }
}()
```

### Reporting Validator Misbehavior

```go
// Report a validator for missing their validation slot
client.ReportMissedValidation(validatorAddress)

// Report a validator for double signing
client.ReportDoubleSign(validatorAddress, blockHash)

// Report a validator for proposing an invalid block
client.ReportInvalidBlock(validatorAddress, blockHash, "Block contains invalid transactions")
```

### Network Management

```go
// Get information about this node
peerInfo := client.PeerInfo()
log.Printf("My peer info: %s", peerInfo)

// List connected peers
peers := client.Peers()
log.Printf("Connected to %d peers", len(peers))

// Connect to a specific peer
err = client.ConnectToPeer(peerAddr)
if err != nil {
    log.Printf("Failed to connect to peer: %v", err)
}
```

## Testing

The consensus client includes comprehensive tests covering:

1. **Basic Functionality**: Tests for client creation, peer info, etc.
2. **Integration**: Tests for communication between multiple clients
3. **Message Types**: Tests for all supported message types
4. **Validator Selection**: Tests for the validator selection mechanism
5. **PubSub Messaging**: Tests for the pubsub messaging system
6. **Validator Monitoring**: Tests for offline validator detection
7. **Evidence Handling**: Tests for reporting and processing evidence

To run the tests:

```bash
cd consensus_client
go test -v
```

For quicker testing during development:

```bash
go test -short
```

## Dependencies

- github.com/ethereum/go-ethereum/common
- github.com/ethereum/go-ethereum/crypto
- github.com/libp2p/go-libp2p
- github.com/libp2p/go-libp2p-pubsub
- github.com/libp2p/go-libp2p/core/host
- github.com/libp2p/go-libp2p/core/peer
- github.com/libp2p/go-libp2p/p2p/discovery/mdns
- github.com/sirupsen/logrus

## Future Improvements

Planned enhancements for the consensus client include:

- Support for additional consensus algorithms (PBFT, Tendermint, etc.)
- Enhanced security features for validator verification
- Improved offline validator detection and reporting
- Optimized message propagation for larger networks
- Integration with more sophisticated block validation mechanisms 