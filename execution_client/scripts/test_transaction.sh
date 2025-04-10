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
    "transactionHash": "2832893f394b8c90e43c3100e2334c2fe843d77aa957b39e64884aed9be12a57",
    "sender": "0x186Dbe76F6B2022b518B4cA42617Ed827aeB7278",
    "receiver": "0xF2bE31c1B5EA7C0AB7C1cBD7609ecF511c8a3CD0",
    "amount": 10,
    "nonce": 1,
    "timestamp": 1744284080,
    "signature": "a9ddeb2f1a2c7111093a260b8045e37c9dc1fdd03f3e472b8df74b2f773b6ca47485bbf186911dc9d0fabd66aa705121c4ea941aee21cfebadcac02288db25ad01"
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