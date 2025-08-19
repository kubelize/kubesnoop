#!/bin/bash

# Build and deploy script for KubeSnoop

set -e

# Configuration
IMAGE_NAME="kubesnoop"
IMAGE_TAG="${1:-latest}"
REGISTRY="${REGISTRY:-}"
NAMESPACE="kubesnoop"
PERSISTENT="${PERSISTENT:-false}"

echo "Building KubeSnoop..."

# Build the Docker image
if [ -n "$REGISTRY" ]; then
    FULL_IMAGE="$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
else
    FULL_IMAGE="$IMAGE_NAME:$IMAGE_TAG"
fi

echo "Building image: $FULL_IMAGE"
docker build -t "$FULL_IMAGE" .

# Push if registry is specified
if [ -n "$REGISTRY" ]; then
    echo "Pushing to registry..."
    docker push "$FULL_IMAGE"
fi

# Deploy to Kubernetes
echo "Deploying to Kubernetes..."

# Create namespace if it doesn't exist
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Apply RBAC
kubectl apply -f deploy/rbac.yaml

# Apply ConfigMap
kubectl apply -f deploy/configmap.yaml

# Choose deployment type
DEPLOYMENT_FILE="deploy/deployment.yaml"
if [ "$PERSISTENT" = "true" ]; then
    DEPLOYMENT_FILE="deploy/deployment-persistent.yaml"
    echo "Using persistent storage for database"
fi

# Update deployment image and apply
if [ -n "$REGISTRY" ]; then
    sed "s|image: kubesnoop:latest|image: $FULL_IMAGE|g" "$DEPLOYMENT_FILE" | kubectl apply -f -
else
    kubectl apply -f "$DEPLOYMENT_FILE"
fi

echo "Deployment complete!"
echo "Check status with: kubectl get pods -n $NAMESPACE"
echo "View logs with: kubectl logs -n $NAMESPACE -l app=kubesnoop"
echo ""
echo "To use persistent storage, set PERSISTENT=true:"
echo "PERSISTENT=true ./scripts/deploy.sh"
