#!/bin/bash

# Local development script

set -e

echo "Running KubeSnoop locally..."

# Build the binary
go build -o bin/kubesnoop ./cmd/kubesnoop

# Run with local kubeconfig
./bin/kubesnoop \
    --kubeconfig ~/.kube/config \
    --format json \
    --output kubesnoop-output.json

echo "Output saved to kubesnoop-output.json"
