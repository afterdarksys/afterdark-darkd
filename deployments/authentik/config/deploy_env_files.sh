#!/bin/bash
# Deploy .env.production files to all services
# Usage: ./deploy_env_files.sh [service-name]
#        ./deploy_env_files.sh all

set -e

CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICES_DIR="$CONFIG_DIR/services"

if [ "$1" = "all" ]; then
    echo "🚀 Deploying .env files to all services..."
    for service_dir in "$SERVICES_DIR"/*; do
        if [ -d "$service_dir" ]; then
            service_name=$(basename "$service_dir")
            echo "  📦 $service_name"
            # TODO: Add your deployment command here
            # Example: scp "$service_dir/.env.production" user@server:/app/.env.production
        fi
    done
elif [ -n "$1" ]; then
    service_dir="$SERVICES_DIR/$1"
    if [ -d "$service_dir" ]; then
        echo "🚀 Deploying .env for $1..."
        # TODO: Add your deployment command here
    else
        echo "❌ Service '$1' not found"
        exit 1
    fi
else
    echo "Usage: $0 [service-name|all]"
    echo ""
    echo "Available services:"
    ls -1 "$SERVICES_DIR"
fi
