package types

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
)

func TestDecodeProvidedMessage() {
	// Base64 data provided by user
	encodedData := "AS7mNJUe9xtGs1ZzPiKSRPIAAAAAAAAAAhSaZ254GlI7XQwOQ3MTE6cIy2B1CCAAAAAAAAAAAAAAAAANzRv5obNs40I37q/vIgkyhGvNggABFPOf1uUarYj29M5quIJyec//uSJmFDql67ENx5fKyChSTlmjM9CjcUQ7AAAAAAAA"

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		log.Fatalf("Failed to decode base64: %v", err)
	}

	fmt.Printf("Raw bytes length: %d\n", len(data))
	fmt.Printf("Raw bytes (hex): %s\n", hex.EncodeToString(data))

	// Try to decode using Go DecodeMessage function
	message, err := DecodeMessage(data)
	if err != nil {
		log.Printf("Failed to decode message: %v", err)

		// Let's try to manually parse the first few fields to see what's wrong
		if len(data) >= 1 {
			fmt.Printf("Version: %d\n", data[0])
		}
		if len(data) >= 9 {
			fmt.Printf("SourceChainSelector: %d\n", uint64(data[1])<<56|uint64(data[2])<<48|uint64(data[3])<<40|uint64(data[4])<<32|uint64(data[5])<<24|uint64(data[6])<<16|uint64(data[7])<<8|uint64(data[8]))
		}
		if len(data) >= 17 {
			fmt.Printf("DestChainSelector: %d\n", uint64(data[9])<<56|uint64(data[10])<<48|uint64(data[11])<<40|uint64(data[12])<<32|uint64(data[13])<<24|uint64(data[14])<<16|uint64(data[15])<<8|uint64(data[16]))
		}
		if len(data) >= 25 {
			fmt.Printf("Nonce/SequenceNumber: %d\n", uint64(data[17])<<56|uint64(data[18])<<48|uint64(data[19])<<40|uint64(data[20])<<32|uint64(data[21])<<24|uint64(data[22])<<16|uint64(data[23])<<8|uint64(data[24]))
		}
		return
	}

	// Print decoded message details
	fmt.Printf("Successfully decoded message:\n")
	fmt.Printf("  Version: %d\n", message.Version)
	fmt.Printf("  SourceChainSelector: %d\n", message.SourceChainSelector)
	fmt.Printf("  DestChainSelector: %d\n", message.DestChainSelector)
	fmt.Printf("  Nonce: %d\n", message.Nonce)
	fmt.Printf("  OnRampAddress: %s (len=%d)\n", hex.EncodeToString(message.OnRampAddress), len(message.OnRampAddress))
	fmt.Printf("  OffRampAddress: %s (len=%d)\n", hex.EncodeToString(message.OffRampAddress), len(message.OffRampAddress))
	fmt.Printf("  Finality: %d\n", message.Finality)
	fmt.Printf("  Sender: %s (len=%d)\n", hex.EncodeToString(message.Sender), len(message.Sender))
	fmt.Printf("  Receiver: %s (len=%d)\n", hex.EncodeToString(message.Receiver), len(message.Receiver))
	fmt.Printf("  DestBlob: %s (len=%d)\n", hex.EncodeToString(message.DestBlob), len(message.DestBlob))
	fmt.Printf("  TokenTransfer: %s (len=%d)\n", hex.EncodeToString(message.TokenTransfer), len(message.TokenTransfer))
	fmt.Printf("  Data: %s (len=%d)\n", hex.EncodeToString(message.Data), len(message.Data))

	// If there's a token transfer, try to decode it too
	if len(message.TokenTransfer) > 0 {
		fmt.Printf("\nDecoding TokenTransfer:\n")
		tokenTransfer, err := DecodeTokenTransfer(message.TokenTransfer)
		if err != nil {
			fmt.Printf("  Failed to decode token transfer: %v\n", err)
		} else {
			fmt.Printf("  Version: %d\n", tokenTransfer.Version)
			fmt.Printf("  Amount: %s\n", tokenTransfer.Amount.String())
			fmt.Printf("  SourceTokenAddress: %s (len=%d)\n", hex.EncodeToString(tokenTransfer.SourceTokenAddress), len(tokenTransfer.SourceTokenAddress))
			fmt.Printf("  DestTokenAddress: %s (len=%d)\n", hex.EncodeToString(tokenTransfer.DestTokenAddress), len(tokenTransfer.DestTokenAddress))
			fmt.Printf("  TokenReceiver: %s (len=%d)\n", hex.EncodeToString(tokenTransfer.TokenReceiver), len(tokenTransfer.TokenReceiver))
			fmt.Printf("  ExtraData: %s (len=%d)\n", hex.EncodeToString(tokenTransfer.ExtraData), len(tokenTransfer.ExtraData))
		}
	}
}
