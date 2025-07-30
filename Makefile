.PHONY: start-consensus start-execution start-all clean build start-separate generate-wallets

# Build both clients
build:
	@echo "Building consensus client..."
	go build -o bin/consensus_client cmd/consensus/main.go
	@echo "Building execution client..."
	go build -o bin/execution_client cmd/execution/main.go

# Start the consensus client
start-consensus:
	@echo "Starting consensus client..."
	go run cmd/consensus/main.go

# Start the execution client
start-execution:
	@echo "Starting execution client..."
	go run cmd/execution/main.go

# Start both clients in parallel
start-all:
	@echo "Starting both consensus and execution clients..."
	@make -j 2 start-consensus start-execution

# Start clients in separate terminals
start-separate:
	@echo "Starting clients in separate terminals..."
	@osascript -e 'tell app "Terminal" to do script "cd $(PWD) && make start-consensus"'
	@osascript -e 'tell app "Terminal" to do script "cd $(PWD) && make start-execution"'

# Generate wallets and transactions
generate-wallets:
	@echo "Generating wallets and transactions..."
	go run cmd/wallet/main.go

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@go clean

