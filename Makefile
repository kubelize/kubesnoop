BINARY_NAME=kubesnoop
BUILD_DIR=bin
DOCKER_IMAGE=kubesnoop
DOCKER_TAG=latest

.PHONY: build clean test docker-build deploy run-local help

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/kubesnoop

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Run linting
lint:
	@echo "Running linter..."
	@golangci-lint run

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Deploy to Kubernetes
deploy: docker-build
	@echo "Deploying to Kubernetes..."
	@./scripts/deploy.sh $(DOCKER_TAG)

# Run locally
run-local: build
	@echo "Running locally..."
	@./scripts/run-local.sh

# Import default rules
import-rules: build
	@echo "Importing default security rules..."
	@./scripts/import-rules.sh

# List security rules
list-rules: build
	@echo "Listing security rules..."
	@./bin/kubesnoop rules list

# Initialize Go modules
mod-tidy:
	@echo "Tidying Go modules..."
	@go mod tidy

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download

# Help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linter"
	@echo "  docker-build  - Build Docker image"
	@echo "  deploy        - Deploy to Kubernetes"
	@echo "  run-local     - Run locally with current kubeconfig"
	@echo "  import-rules  - Import default security rules"
	@echo "  list-rules    - List all security rules"
	@echo "  mod-tidy      - Tidy Go modules"
	@echo "  deps          - Download dependencies"
	@echo "  help          - Show this help"
