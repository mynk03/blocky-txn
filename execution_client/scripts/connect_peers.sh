#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Node URLs
NODE1_URL="http://localhost:8081"
NODE2_URL="http://localhost:8082"

echo -e "${GREEN}Starting peer connection test...${NC}"

# Function to make curl request and format response
make_request() {
    local url=$1
    local method=$2
    local data=$3
    local description=$4
    
    echo -e "\n${GREEN}$description${NC}"
    
    if [ -z "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" "$url")
    else
        response=$(curl -s -X "$method" -H "Content-Type: application/json" -d "$data" -w "\n%{http_code}" "$url")
    fi
    
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    echo "Response:"
    echo "Status Code: $status_code"
    if [ ! -z "$body" ]; then
        echo "Body:"
        echo "$body" | jq '.'
    fi
    echo "----------------------------------------"
}

# Get Node 1's peer ID
echo -e "\n${GREEN}Getting Node 1's peer ID...${NC}"
NODE1_PEER_ID=$(curl -s "$NODE1_URL/node/id")
echo "Node 1 Peer ID: $NODE1_PEER_ID"

# Connect Node 2 to Node 1
echo -e "\n${GREEN}Connecting Node 2 to Node 1...${NC}"
make_request "$NODE2_URL/test/peer/connect" "POST" "{\"peerAddr\":\"$NODE1_PEER_ID\"}" "Connecting Node 2 to Node 1"

# Wait for connection to establish
echo -e "\n${GREEN}Waiting for connection to establish...${NC}"
sleep 2

# Check Node 1's peers
echo -e "\n${GREEN}Checking Node 1's peers...${NC}"
make_request "$NODE1_URL/test/peers" "GET" "" "Node 1's peers"

# Check Node 2's peers
echo -e "\n${GREEN}Checking Node 2's peers...${NC}"
make_request "$NODE2_URL/test/peers" "GET" "" "Node 2's peers"

echo -e "\n${GREEN}Test completed!${NC}" 