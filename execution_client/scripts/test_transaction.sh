#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Node URLs
NODE1_URL="http://localhost:8081"
NODE2_URL="http://localhost:8082"

# Get the root directory (two levels up from the script location)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Load environment variables from root directory
if [ -f "$ROOT_DIR/.env" ]; then
    export $(cat "$ROOT_DIR/.env" | grep -v '^#' | xargs)
else
    echo -e "${RED}Error: .env file not found in root directory${NC}"
    echo -e "${GREEN}Looking for .env in:${NC} ${BLUE}$ROOT_DIR${NC}"
    exit 1
fi

# Check if TRANSACTIONS_PATH is set, otherwise use default
if [ -z "$TRANSACTIONS_PATH" ]; then
    echo -e "${GREEN}TRANSACTIONS_PATH not set in .env file${NC}"
    echo -e "${GREEN}Using default path:${NC} ${BLUE}chain_data/genesis_data/initial_users/mock_transactions.json${NC}"
    TRANSACTIONS_PATH="$ROOT_DIR/chain_data/genesis_data/initial_users/mock_transactions.json"
fi

# Check if transactions file exists
if [ ! -f "$TRANSACTIONS_PATH" ]; then
    echo -e "${RED}Error: Transactions file not found at $TRANSACTIONS_PATH${NC}"
    exit 1
fi

echo -e "${GREEN}Starting transaction broadcast test...${NC}"

# Function to make curl request and format response
make_request() {
    local url=$1
    local method=$2
    local data=$3
    local description=$4
    
    echo -e "\n${GREEN}$description${NC}"
    
    # Print the complete request
    echo -e "${BLUE}Request:${NC}"
    echo "URL: $url"
    echo "Method: $method"
    echo "Data:"
    echo "$data" | jq '.'
    echo "----------------------------------------"
    
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

# Get the number of transactions in the file
TRANSACTION_COUNT=$(jq 'length' "$TRANSACTIONS_PATH")
echo -e "${GREEN}Found $TRANSACTION_COUNT transactions in file${NC}"

# Send each transaction to Node 1
for ((i=0; i<TRANSACTION_COUNT; i++)); do
    # Extract one transaction at a time
    TX=$(jq -c ".[$i]" "$TRANSACTIONS_PATH")
    echo -e "\n${GREEN}Sending transaction $((i+1)) of $TRANSACTION_COUNT${NC}"
    make_request "$NODE1_URL/transaction" "POST" "$TX" "Sending transaction to Node 1"
    echo -e "${GREEN}Waiting 2 seconds before next transaction...${NC}"
    sleep 2
done

# Wait for transactions to be broadcasted
echo -e "\n${GREEN}Waiting for transactions to be broadcasted...${NC}"
sleep 5

# Get transactions from both nodes
echo -e "\n${GREEN}Getting transactions from Node 1...${NC}"
NODE1_TXS=$(curl -s "$NODE1_URL/txn/pool/transactions" | jq -c '.transactions[]')
echo -e "\n${GREEN}Getting transactions from Node 2...${NC}"
NODE2_TXS=$(curl -s "$NODE2_URL/txn/pool/transactions" | jq -c '.transactions[]')

# Compare transactions
echo -e "\n${GREEN}Comparing transactions...${NC}"
NODE1_COUNT=$(echo "$NODE1_TXS" | wc -l)
NODE2_COUNT=$(echo "$NODE2_TXS" | wc -l)

if [ "$NODE1_COUNT" -eq "$NODE2_COUNT" ] && [ "$NODE1_COUNT" -ne 0 ]; then
    echo -e "${GREEN}Success: Both nodes have the same number of transactions ($NODE1_COUNT)${NC}"
    
    # Compare transaction hashes
    NODE1_HASHES=$(echo "$NODE1_TXS" | jq -r '.transactionHash' | sort)
    NODE2_HASHES=$(echo "$NODE2_TXS" | jq -r '.transactionHash' | sort)
    
    if [ "$NODE1_HASHES" = "$NODE2_HASHES" ]; then
        echo -e "${GREEN}Success: All transaction hashes match between nodes${NC}"
    else
        echo -e "${RED}Error: Transaction hashes do not match between nodes${NC}"
        echo "Node 1 hashes:"
        echo "$NODE1_HASHES"
        echo "Node 2 hashes:"
        echo "$NODE2_HASHES"
    fi
else
    echo -e "${RED}Error: Node 1 has $NODE1_COUNT transactions, Node 2 has $NODE2_COUNT transactions${NC}"
fi

# Detailed transaction comparison
echo -e "\n${YELLOW}=== Detailed Transaction Comparison ===${NC}"

# Node 1 transactions
echo -e "\n${BLUE}Node 1 Transactions:${NC}"
if [ -z "$NODE1_TXS" ]; then
    echo "No transactions found in Node 1"
else
    echo "$NODE1_TXS" | jq -c '.'
fi

# Node 2 transactions
echo -e "\n${BLUE}Node 2 Transactions:${NC}"
if [ -z "$NODE2_TXS" ]; then
    echo "No transactions found in Node 2"
else
    echo "$NODE2_TXS" | jq -c '.'
fi

sleep 4 

# Compare each transaction
echo -e "\n${YELLOW}=== Transaction-by-Transaction Comparison ===${NC}"
if [ ! -z "$NODE1_TXS" ] && [ ! -z "$NODE2_TXS" ]; then
    # Convert to arrays for easier comparison
    NODE1_ARRAY=($(echo "$NODE1_TXS" | jq -c '.'))
    NODE2_ARRAY=($(echo "$NODE2_TXS" | jq -c '.'))
    
    for i in "${!NODE1_ARRAY[@]}"; do
        echo -e "\n${GREEN}Transaction $((i+1)):${NC}"
        echo -e "${BLUE}Node 1:${NC}"
        echo "${NODE1_ARRAY[$i]}" | jq '.'
        echo -e "${BLUE}Node 2:${NC}"
        echo "${NODE2_ARRAY[$i]}" | jq '.'
        
        # Compare transaction hashes
        NODE1_HASH=$(echo "${NODE1_ARRAY[$i]}" | jq -r '.transactionHash')
        NODE2_HASH=$(echo "${NODE2_ARRAY[$i]}" | jq -r '.transactionHash')
        
        if [ "$NODE1_HASH" = "$NODE2_HASH" ]; then
            echo -e "${GREEN}✓ Transaction hashes match${NC}"
        else
            echo -e "${RED}✗ Transaction hashes do not match${NC}"
        fi
    done
fi

echo -e "\n${GREEN}Test completed!${NC}" 