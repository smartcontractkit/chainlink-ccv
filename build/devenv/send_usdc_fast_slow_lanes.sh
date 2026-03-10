#!/usr/bin/env bash
# Send 1 fast USDC transfer (finality=1) and 1 slow USDC transfer (finality=0)
# on every possible lane between Ethereum Sepolia, Polygon Amoy, Avalanche Fuji,
# Base Sepolia, and Arbitrum Sepolia.
#
# Usage: ./send_usdc_fast_slow_lanes.sh
# Uses --omit-committee for CCTP-only sends. Optional env: RECEIVER_ADDRESS, ENV (default staging), AMOUNT (default 1000000)

set -e

RECEIVER_ADDRESS="${RECEIVER_ADDRESS:-0x269895AC2a2eC6e1Df37F68AcfbBDa53e62b71B1}"
ENV="${ENV:-staging}"
AMOUNT="${AMOUNT:-1000000}"

# Chain selector : USDC (testnet). Run from build/devenv so ccv is on PATH.
# Ethereum Sepolia, Polygon Amoy, Avalanche Fuji, Base Sepolia, Arbitrum Sepolia
# https://developers.circle.com/stablecoins/usdc-contract-addresses

# --- Ethereum Sepolia (16015286601757825753) USDC 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 ---
# -> Polygon Amoy
ccv send --omit-committee --dest 16281711391670634445 --src 16015286601757825753 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" --finality 1
ccv send --omit-committee --dest 16281711391670634445 --src 16015286601757825753 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" --finality 0
# -> Avalanche Fuji
ccv send --omit-committee --dest 14767482510784806043 --src 16015286601757825753 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" --finality 1
ccv send --omit-committee --dest 14767482510784806043 --src 16015286601757825753 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" --finality 0
# -> Base Sepolia
ccv send --omit-committee --dest 10344971235874465080 --src 16015286601757825753 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" --finality 1
ccv send --omit-committee --dest 10344971235874465080 --src 16015286601757825753 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" --finality 0
# -> Arbitrum Sepolia
ccv send --omit-committee --dest 3478487238524512106 --src 16015286601757825753 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" --finality 1
ccv send --omit-committee --dest 3478487238524512106 --src 16015286601757825753 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" --finality 0

# --- Polygon Amoy (16281711391670634445) USDC 0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582 ---
ccv send --omit-committee --dest 16015286601757825753 --src 16281711391670634445 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582" --finality 1
ccv send --omit-committee --dest 16015286601757825753 --src 16281711391670634445 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582" --finality 0
ccv send --omit-committee --dest 14767482510784806043 --src 16281711391670634445 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582" --finality 1
ccv send --omit-committee --dest 14767482510784806043 --src 16281711391670634445 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582" --finality 0
ccv send --omit-committee --dest 10344971235874465080 --src 16281711391670634445 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582" --finality 1
ccv send --omit-committee --dest 10344971235874465080 --src 16281711391670634445 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582" --finality 0
ccv send --omit-committee --dest 3478487238524512106 --src 16281711391670634445 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582" --finality 1
ccv send --omit-committee --dest 3478487238524512106 --src 16281711391670634445 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582" --finality 0

# --- Avalanche Fuji (14767482510784806043) USDC 0x5425890298aed601595a70AB815c96711a31Bc65 ---
ccv send --omit-committee --dest 16015286601757825753 --src 14767482510784806043 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x5425890298aed601595a70AB815c96711a31Bc65" --finality 1
ccv send --omit-committee --dest 16015286601757825753 --src 14767482510784806043 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x5425890298aed601595a70AB815c96711a31Bc65" --finality 0
ccv send --omit-committee --dest 16281711391670634445 --src 14767482510784806043 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x5425890298aed601595a70AB815c96711a31Bc65" --finality 1
ccv send --omit-committee --dest 16281711391670634445 --src 14767482510784806043 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x5425890298aed601595a70AB815c96711a31Bc65" --finality 0
ccv send --omit-committee --dest 10344971235874465080 --src 14767482510784806043 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x5425890298aed601595a70AB815c96711a31Bc65" --finality 1
ccv send --omit-committee --dest 10344971235874465080 --src 14767482510784806043 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x5425890298aed601595a70AB815c96711a31Bc65" --finality 0
ccv send --omit-committee --dest 3478487238524512106 --src 14767482510784806043 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x5425890298aed601595a70AB815c96711a31Bc65" --finality 1
ccv send --omit-committee --dest 3478487238524512106 --src 14767482510784806043 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x5425890298aed601595a70AB815c96711a31Bc65" --finality 0

# --- Base Sepolia (10344971235874465080) USDC 0x036CbD53842c5426634e7929541eC2318f3dCF7e ---
ccv send --omit-committee --dest 16015286601757825753 --src 10344971235874465080 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x036CbD53842c5426634e7929541eC2318f3dCF7e" --finality 1
ccv send --omit-committee --dest 16015286601757825753 --src 10344971235874465080 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x036CbD53842c5426634e7929541eC2318f3dCF7e" --finality 0
ccv send --omit-committee --dest 16281711391670634445 --src 10344971235874465080 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x036CbD53842c5426634e7929541eC2318f3dCF7e" --finality 1
ccv send --omit-committee --dest 16281711391670634445 --src 10344971235874465080 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x036CbD53842c5426634e7929541eC2318f3dCF7e" --finality 0
ccv send --omit-committee --dest 14767482510784806043 --src 10344971235874465080 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x036CbD53842c5426634e7929541eC2318f3dCF7e" --finality 1
ccv send --omit-committee --dest 14767482510784806043 --src 10344971235874465080 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x036CbD53842c5426634e7929541eC2318f3dCF7e" --finality 0
ccv send --omit-committee --dest 3478487238524512106 --src 10344971235874465080 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x036CbD53842c5426634e7929541eC2318f3dCF7e" --finality 1
ccv send --omit-committee --dest 3478487238524512106 --src 10344971235874465080 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x036CbD53842c5426634e7929541eC2318f3dCF7e" --finality 0

# --- Arbitrum Sepolia (3478487238524512106) USDC 0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d ---
ccv send --omit-committee --dest 16015286601757825753 --src 3478487238524512106 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" --finality 1
ccv send --omit-committee --dest 16015286601757825753 --src 3478487238524512106 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" --finality 0
ccv send --omit-committee --dest 16281711391670634445 --src 3478487238524512106 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" --finality 1
ccv send --omit-committee --dest 16281711391670634445 --src 3478487238524512106 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" --finality 0
ccv send --omit-committee --dest 14767482510784806043 --src 3478487238524512106 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" --finality 1
ccv send --omit-committee --dest 14767482510784806043 --src 3478487238524512106 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" --finality 0
ccv send --omit-committee --dest 10344971235874465080 --src 3478487238524512106 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" --finality 1
ccv send --omit-committee --dest 10344971235874465080 --src 3478487238524512106 --env="$ENV" --receiver-address="$RECEIVER_ADDRESS" --token "${AMOUNT}:0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d" --finality 0

echo "Done. Sent 1 fast (finality=1) + 1 slow (finality=0) USDC transfer on each of 20 lanes (40 messages)."
