#!/bin/bash

# Function to print colored output
print_header() {
    echo -e "\n\033[1;34m$1\033[0m"
}

# Function to make API requests
make_request() {
    local method=$1
    local url=$2
    local data=$3
    
    echo -e "\n\033[1;33mRequest:\033[0m"
    echo "curl -X $method $url $data"
    
    echo -e "\n\033[1;32mResponse:\033[0m"
    if [ -z "$data" ]; then
        curl -X $method $url
    else
        curl -X $method $url -H "Content-Type: application/json" -d "$data"
    fi
    echo -e "\n----------------------------------------"
}

# Test Node 0 (port 8080)
print_header "Testing Node 0 (port 8080)"

# 1. Get Node ID
print_header "1. Get Node ID"
make_request "GET" "http://localhost:8080/node/id"

# 2. Get All Transactions (initially empty)
print_header "2. Get All Transactions"
make_request "GET" "http://localhost:8080/transactions"

# 3. Send a Transaction
print_header "3. Send a Transaction"
TRANSACTION_DATA='{
    "from": "0x1",
    "to": "0x2",
    "amount": 100,
    "nonce": 1,
    "block_number": 0,
    "signature": "0x1234567890abcdef"
}'
make_request "POST" "http://localhost:8080/transaction" "$TRANSACTION_DATA"

# 4. Get All Transactions (should show the new transaction)
print_header "4. Get All Transactions (after sending)"
make_request "GET" "http://localhost:8080/transactions"

# 5. Get All Peers (testing endpoint)
print_header "5. Get All Peers"
make_request "GET" "http://localhost:8080/test/peers"

# 6. Connect to Peer (testing endpoint)
print_header "6. Connect to Peer"
PEER_DATA='{
    "address": "http://localhost:8081"
}'
make_request "POST" "http://localhost:8080/test/peer/connect" "$PEER_DATA"

# Test Node 1 (port 8081)
print_header "\nTesting Node 1 (port 8081)"

# 1. Get Node ID
print_header "1. Get Node ID"
make_request "GET" "http://localhost:8081/node/id"

# 2. Get All Transactions
print_header "2. Get All Transactions"
make_request "GET" "http://localhost:8081/transactions"

# 3. Send a Transaction
print_header "3. Send a Transaction"
TRANSACTION_DATA='{
    "from": "0x2",
    "to": "0x3",
    "amount": 200,
    "nonce": 1,
    "block_number": 0,
    "signature": "0xabcdef1234567890"
}'
make_request "POST" "http://localhost:8081/transaction" "$TRANSACTION_DATA"

# Test Node 2 (port 8082)
print_header "\nTesting Node 2 (port 8082)"

# 1. Get Node ID
print_header "1. Get Node ID"
make_request "GET" "http://localhost:8082/node/id"

# 2. Get All Transactions
print_header "2. Get All Transactions"
make_request "GET" "http://localhost:8082/transactions"

# 3. Send a Transaction
print_header "3. Send a Transaction"
TRANSACTION_DATA='{
    "from": "0x3",
    "to": "0x1",
    "amount": 300,
    "nonce": 1,
    "block_number": 0,
    "signature": "0x7890abcdef123456"
}'
make_request "POST" "http://localhost:8082/transaction" "$TRANSACTION_DATA" 