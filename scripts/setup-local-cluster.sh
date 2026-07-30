#!/usr/bin/env bash
# Sets up a local kind cluster with a local Docker registry.
# The local registry avoids pulling from Docker Hub (works behind corporate proxies).
#
# Usage: ./scripts/setup-local-cluster.sh
# Teardown: kind delete cluster --name ledger-local && docker rm -f kind-registry

set -euo pipefail

CLUSTER_NAME="ledger-local"
REGISTRY_PORT="5001"

echo "[1/4] Starting local Docker registry..."
if ! docker ps --format '{{.Names}}' | grep -q "^kind-registry$"; then
  docker run -d --name kind-registry --restart=always -p "127.0.0.1:${REGISTRY_PORT}:5000" registry:2
fi

echo "[2/4] Creating kind cluster with registry support..."
cat <<EOF | kind create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${REGISTRY_PORT}"]
      endpoint = ["http://kind-registry:5000"]
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      - containerPort: 80
        hostPort: 8080
      - containerPort: 443
        hostPort: 8443
EOF

echo "[3/4] Connecting registry to cluster network..."
docker network connect kind kind-registry 2>/dev/null || true

echo "[4/4] Switching kubectl context..."
kubectl config use-context "kind-${CLUSTER_NAME}"

echo "Done! Push images with: docker tag <img> localhost:${REGISTRY_PORT}/<img> && docker push localhost:${REGISTRY_PORT}/<img>"
