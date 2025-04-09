#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Node URLs
NODE1_URL="http://localhost:8081"
NODE2_URL="http://localhost:8082"

echo -e "${GREEN}Starting transaction broadcast test...${NC}"

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

# Create a test transaction
echo -e "\n${GREEN}Creating test transaction...${NC}"
TX_DATA='{
    "transactionHash": "0x14a24eb3539734dc81278f21dbafc8cfc29b7f11f316fe27b2e9ac1eff903ba8",
    "sender": "0x89c09085Dbba562b54a7C6D55617697e07398cdC",
    "receiver": "0xf924cbdb6eBeba80B9fd0dbEf8d16B6211Bab649",
    "amount": 10,
    "nonce": 1,
    "timestamp": 1744204856,
    "signature": "fabfae22fca0015e70ddc1f06d518e3a3c91941805308c8e909765c5ea40a56f2711d750178ae27736309d51b382ebff8976f8e677c64fc2daf6a5fe32b580c201"
  }'

# Send transaction to Node 1
make_request "$NODE1_URL/transaction" "POST" "$TX_DATA" "Sending transaction to Node 1"

# Wait for transaction to be broadcasted
echo -e "\n${GREEN}Waiting for transaction to be broadcasted...${NC}"
sleep 2

# Check Node 1's transaction pool
make_request "$NODE1_URL/transactions" "GET" "" "Checking Node 1's transaction pool"

# Check Node 2's transaction pool
make_request "$NODE2_URL/transactions" "GET" "" "Checking Node 2's transaction pool"

# Get Node 1's peers
make_request "$NODE1_URL/test/peers" "GET" "" "Getting Node 1's peers"

# Get all transactions from Node 1's pool
make_request "$NODE1_URL/transactions" "GET" "" "Getting all transactions from Node 1's pool"

# Get all transactions from Node 2's pool
make_request "$NODE2_URL/transactions" "GET" "" "Getting all transactions from Node 2's pool"

echo -e "\n${GREEN}Test completed!${NC}" 