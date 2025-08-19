#!/bin/bash

# Test script to validate KubeSnoop functionality

set -e

echo "KubeSnoop Validation Tests"
echo "=========================="

# Test 1: Help command
echo "Testing help command..."
./bin/kubesnoop --help > /dev/null
echo "✅ Help command works"

# Test 2: Version information (cluster connection test)
echo "Testing cluster connectivity..."
if ./bin/kubesnoop --format json --output /dev/null 2>/dev/null; then
    echo "✅ Cluster connectivity test passed"
else
    echo "⚠️  Cluster connectivity test failed (this is expected if no cluster is available)"
fi

# Test 3: Configuration validation
echo "Testing configuration..."
if [ -f "examples/kubesnoop.yaml" ]; then
    echo "✅ Example configuration found"
else
    echo "❌ Example configuration missing"
fi

# Test 4: Docker build test (if Docker is available)
if command -v docker &> /dev/null; then
    echo "Testing Docker build..."
    if docker build -t kubesnoop-test . > /dev/null 2>&1; then
        echo "✅ Docker build successful"
        docker rmi kubesnoop-test > /dev/null 2>&1
    else
        echo "❌ Docker build failed"
    fi
else
    echo "⚠️  Docker not available, skipping Docker build test"
fi

echo ""
echo "Validation complete!"
echo ""
echo "Next steps:"
echo "1. Make sure you have a Kubernetes cluster available"
echo "2. Run: ./scripts/run-local.sh"
echo "3. Or deploy to cluster: ./scripts/deploy.sh"
