#!/bin/bash

# Script to verify WavePointToken on Basescan
# Prerequisites:
# 1. Get a free API key from https://basescan.org/apis
# 2. Add BASESCAN_API_KEY to .env file

set -e

CONTRACT_ADDRESS="0xC9c9C776C45768Ce84ECb3526AE05d02AEFf290F"
CONTRACT_NAME="src/WavePointToken.sol:WavePointToken"

# Load variables from .env
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Verify that API key is configured
if [ -z "$BASESCAN_API_KEY" ]; then
    echo "❌ Error: BASESCAN_API_KEY not found in .env file"
    echo ""
    echo "To get an API key:"
    echo "1. Go to https://basescan.org/apis"
    echo "2. Create an account (free)"
    echo "3. Generate an API key"
    echo "4. Add to .env file: BASESCAN_API_KEY=your_api_key_here"
    exit 1
fi

echo "🔍 Verifying contract on Basescan..."
echo "📍 Address: $CONTRACT_ADDRESS"
echo ""

# Build constructor arguments
CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(string,string,address,address)" \
    "1Wave Points" \
    "WAVE" \
    0x49C562a15b05ffD5fDFf57BD3c7a9e346e4a2b39 \
    0x49C562a15b05ffD5fDFf57BD3c7a9e346e4a2b39)

# Verify the contract
forge verify-contract \
    --chain-id 8453 \
    --num-of-optimizations 200 \
    --compiler-version 0.8.30 \
    --watch \
    --constructor-args "$CONSTRUCTOR_ARGS" \
    "$CONTRACT_ADDRESS" \
    "$CONTRACT_NAME" \
    --etherscan-api-key "$BASESCAN_API_KEY"

echo ""
echo "✅ Verification completed!"
echo "🔗 View at: https://basescan.org/address/$CONTRACT_ADDRESS#code"
