#!/bin/bash

set -e

echo "🔧 SecurityClaw Docker Onboarding Script"
echo "=========================================="

# Check if config.yaml exists
if [ ! -f "config.yaml" ]; then
    echo "❌ config.yaml not found!"
    echo ""
    echo "Would you like to run the Python onboarding first?"
    echo "This will interactively configure SecurityClaw (Ollama, OpenSearch, etc.)."
    read -p "Run Python onboarding? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Running: python main.py onboard"
        python main.py onboard
    else
        echo "Skipping onboarding. Please create config.yaml manually or run python main.py onboard"
        exit 1
    fi
fi

echo "✅ config.yaml found!"
echo ""

# Extract Ollama settings from config.yaml
OLLAMA_BASE_URL=$(grep -A 5 "^llm:" config.yaml | grep "ollama_base_url:" | awk '{print $2}' | tr -d '"')
OLLAMA_MODEL=$(grep -A 5 "^llm:" config.yaml | grep "ollama_model:" | awk '{print $2}' | tr -d '"')
OLLAMA_EMBED_MODEL=$(grep -A 5 "^llm:" config.yaml | grep "ollama_embed_model:" | awk '{print $2}' | tr -d '"')

echo "📋 Ollama Configuration from config.yaml:"
echo "  Base URL: $OLLAMA_BASE_URL"
echo "  Model: $OLLAMA_MODEL"
echo "  Embed Model: $OLLAMA_EMBED_MODEL"
echo ""

# Convert localhost to host.docker.internal for Docker
if [[ $OLLAMA_BASE_URL == *"localhost"* ]] || [[ $OLLAMA_BASE_URL == *"127.0.0.1"* ]]; then
    DOCKER_OLLAMA_URL=$(echo "$OLLAMA_BASE_URL" | sed 's/localhost/host.docker.internal/' | sed 's/127.0.0.1/host.docker.internal/')
    echo "🐳 Docker will use: $DOCKER_OLLAMA_URL (converted from localhost)"
else
    DOCKER_OLLAMA_URL=$OLLAMA_BASE_URL
    echo "🐳 Docker will use: $DOCKER_OLLAMA_URL"
fi
echo ""

# Check if Ollama is reachable before spinning up Docker
echo "🔍 Testing Ollama reachability at $OLLAMA_BASE_URL..."
if timeout 3 curl -s "$OLLAMA_BASE_URL/api/tags" > /dev/null 2>&1; then
    echo "✅ Ollama is reachable!"
else
    echo "⚠️  Ollama does not appear to be running at $OLLAMA_BASE_URL"
    echo "   Make sure Ollama is running on your host machine before starting Docker."
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "🚀 Starting Docker Compose..."
echo ""

# Export environment variables for docker-compose to pick up
export OLLAMA_BASE_URL="$DOCKER_OLLAMA_URL"
export OLLAMA_MODEL="$OLLAMA_MODEL"
export OLLAMA_EMBED_MODEL="$OLLAMA_EMBED_MODEL"

# Start docker-compose
docker-compose up
