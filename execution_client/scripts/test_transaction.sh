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
    "transactionHash": "4e78eac9860d8596e442b3370dd2021ebdf178ed372161804927caef0076620f",
    "sender": "0x6eCD8F1B06B53831Ada85Ee7Ee1F3d5be6ef4c98",
    "receiver": "0x915767829d0bE617726342D33Be8bB72099a1d65",
    "amount": 10,
    "nonce": 1,
    "timestamp": 1744294774,
    "signature": "e9005501b208eb1f352975119aae5b40a019b884c2be730acf04245371c0da1b6303c12bc9d2ef145fd1b33b25e24a6cb8e4db1c82a2f265ad8ab3d8d072957c00"
  }'

# Send transaction to Node 1
make_request "$NODE1_URL/transaction" "POST" "$TX_DATA" "Sending transaction to Node 1"

# Wait for transaction to be broadcasted
echo -e "\n${GREEN}Waiting for transaction to be broadcasted...${NC}"
sleep 5

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