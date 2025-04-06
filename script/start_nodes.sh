#!/bin/bash

# Function to start a node
start_node() {
    local port=$1
    local validator_addr=$2
    local bootstrap_addr=$3
    
    # Create a new terminal window and start the node
    osascript -e "tell application \"Terminal\" to do script \"cd $(pwd) && go run main.go -port $port -validator $validator_addr $bootstrap_addr\""
}

# Clean up any existing ChainData directories
rm -rf ChainData

# Start node 0 (bootstrap node)
echo "Starting bootstrap node (node 0) on port 8080..."
start_node "8080" "0x1" ""

# Wait for bootstrap node to start
sleep 3

# Start node 1 and connect to node 0
echo "Starting node 1 on port 8081..."
start_node "8081" "0x2" "-bootstrap http://localhost:8080"

# Start node 2 and connect to node 0
echo "Starting node 2 on port 8082..."
start_node "8082" "0x3" "-bootstrap http://localhost:8080"

echo "All nodes started. You can now send transactions to any node."
echo "Node 0: http://localhost:8080"
echo "Node 1: http://localhost:8081"
echo "Node 2: http://localhost:8082" 