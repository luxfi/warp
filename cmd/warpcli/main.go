// Copyright (C) 2025, Lux Industries, Inc.
// See the file LICENSE for licensing terms.

package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/luxfi/warp/types"
	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "warp",
	Short: "Warp V2 - Cross-chain messaging protocol CLI",
	Long: `Warp V2 is an enhanced cross-chain messaging (XCM) protocol with 
post-quantum safety and private messaging capabilities.

This CLI provides tools for creating, signing, and verifying cross-chain messages.`,
	Version: fmt.Sprintf("%s (built %s)", version, buildDate),
}

func init() {
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(encodeCmd)
	rootCmd.AddCommand(decodeCmd)
	rootCmd.AddCommand(serveCmd)
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new Warp message",
	Long:  `Create a new cross-chain message with specified source, destination, and payload.`,
	Run: func(cmd *cobra.Command, args []string) {
		sourceChain, _ := cmd.Flags().GetString("source")
		destChain, _ := cmd.Flags().GetString("dest")
		payload, _ := cmd.Flags().GetString("payload")
		
		// Convert chain IDs from hex strings
		sourceID, err := hexToID(sourceChain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid source chain ID: %v\n", err)
			os.Exit(1)
		}
		
		destID, err := hexToID(destChain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid destination chain ID: %v\n", err)
			os.Exit(1)
		}
		
		// Create message
		msg := &SimpleMessage{
			sourceID: sourceID,
			destID:   destID,
			payload:  []byte(payload),
		}
		
		// Generate message ID
		serialized, _ := msg.Serialize()
		msg.id = types.ID(hashBytes(serialized))
		
		// Output message details
		fmt.Printf("Message created:\n")
		fmt.Printf("  ID: %x\n", msg.ID())
		fmt.Printf("  Source Chain: %x\n", msg.SourceChainID())
		fmt.Printf("  Destination Chain: %x\n", msg.DestinationChainID())
		fmt.Printf("  Payload: %s\n", msg.Payload())
		fmt.Printf("  Serialized: %x\n", serialized)
	},
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a Warp message",
	Long:  `Sign a serialized Warp message using a private key.`,
	Run: func(cmd *cobra.Command, args []string) {
		messageHex, _ := cmd.Flags().GetString("message")
		keyFile, _ := cmd.Flags().GetString("key")
		
		// Decode message
		messageBytes, err := hex.DecodeString(messageHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid message hex: %v\n", err)
			os.Exit(1)
		}
		
		// TODO: Load private key from file and sign
		fmt.Printf("Message to sign: %x\n", messageBytes)
		fmt.Printf("Key file: %s\n", keyFile)
		fmt.Println("Signing functionality will be implemented with BLS integration")
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a signed Warp message",
	Long:  `Verify a Warp message signature against a validator set.`,
	Run: func(cmd *cobra.Command, args []string) {
		messageHex, _ := cmd.Flags().GetString("message")
		signatureHex, _ := cmd.Flags().GetString("signature")
		
		// Decode inputs
		messageBytes, err := hex.DecodeString(messageHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid message hex: %v\n", err)
			os.Exit(1)
		}
		
		signatureBytes, err := hex.DecodeString(signatureHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid signature hex: %v\n", err)
			os.Exit(1)
		}
		
		// TODO: Implement verification with validator set
		fmt.Printf("Message: %x\n", messageBytes)
		fmt.Printf("Signature: %x\n", signatureBytes)
		fmt.Println("Verification functionality will be implemented with validator set integration")
	},
}

var encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Encode data for Warp messages",
	Long:  `Encode various data types for use in Warp messages.`,
	Run: func(cmd *cobra.Command, args []string) {
		data, _ := cmd.Flags().GetString("data")
		format, _ := cmd.Flags().GetString("format")
		
		switch format {
		case "hex":
			fmt.Printf("%x\n", []byte(data))
		case "base64":
			// TODO: Add base64 encoding
			fmt.Println("Base64 encoding not yet implemented")
		default:
			fmt.Printf("%x\n", []byte(data))
		}
	},
}

var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decode Warp message data",
	Long:  `Decode hex-encoded Warp message data.`,
	Run: func(cmd *cobra.Command, args []string) {
		dataHex, _ := cmd.Flags().GetString("data")
		
		data, err := hex.DecodeString(dataHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid hex data: %v\n", err)
			os.Exit(1)
		}
		
		// Try to parse as a message
		if len(data) >= 96 { // Minimum message size (3 * 32 bytes)
			fmt.Println("Decoded as potential message:")
			fmt.Printf("  Source Chain ID: %x\n", data[0:32])
			fmt.Printf("  Destination Chain ID: %x\n", data[32:64])
			fmt.Printf("  Payload: %s\n", data[64:])
		} else {
			fmt.Printf("Decoded data: %s\n", string(data))
		}
	},
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run Warp message relay server",
	Long:  `Start a server that can relay Warp messages between chains.`,
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")
		dev, _ := cmd.Flags().GetBool("dev")
		
		fmt.Printf("Starting Warp relay server on port %d\n", port)
		if dev {
			fmt.Println("Running in development mode")
		}
		
		// TODO: Implement server functionality
		fmt.Println("Server functionality will be implemented with network integration")
	},
}

func init() {
	// Create command flags
	createCmd.Flags().StringP("source", "s", "", "Source chain ID (hex)")
	createCmd.Flags().StringP("dest", "d", "", "Destination chain ID (hex)")
	createCmd.Flags().StringP("payload", "p", "", "Message payload")
	createCmd.MarkFlagRequired("source")
	createCmd.MarkFlagRequired("dest")
	createCmd.MarkFlagRequired("payload")
	
	// Sign command flags
	signCmd.Flags().StringP("message", "m", "", "Serialized message (hex)")
	signCmd.Flags().StringP("key", "k", "", "Private key file")
	signCmd.MarkFlagRequired("message")
	signCmd.MarkFlagRequired("key")
	
	// Verify command flags
	verifyCmd.Flags().StringP("message", "m", "", "Serialized message (hex)")
	verifyCmd.Flags().StringP("signature", "s", "", "Signature (hex)")
	verifyCmd.MarkFlagRequired("message")
	verifyCmd.MarkFlagRequired("signature")
	
	// Encode command flags
	encodeCmd.Flags().StringP("data", "d", "", "Data to encode")
	encodeCmd.Flags().StringP("format", "f", "hex", "Output format (hex, base64)")
	encodeCmd.MarkFlagRequired("data")
	
	// Decode command flags
	decodeCmd.Flags().StringP("data", "d", "", "Hex data to decode")
	decodeCmd.MarkFlagRequired("data")
	
	// Serve command flags
	serveCmd.Flags().IntP("port", "p", 9650, "Server port")
	serveCmd.Flags().Bool("dev", false, "Run in development mode")
}

// SimpleMessage implements the types.Message interface
type SimpleMessage struct {
	id       types.ID
	sourceID types.ID
	destID   types.ID
	payload  []byte
}

func (m *SimpleMessage) ID() types.ID                  { return m.id }
func (m *SimpleMessage) SourceChainID() types.ID       { return m.sourceID }
func (m *SimpleMessage) DestinationChainID() types.ID { return m.destID }
func (m *SimpleMessage) Payload() []byte               { return m.payload }
func (m *SimpleMessage) Serialize() ([]byte, error) {
	result := make([]byte, 0, 32*2+len(m.payload))
	result = append(result, m.sourceID[:]...)
	result = append(result, m.destID[:]...)
	result = append(result, m.payload...)
	return result, nil
}

// Helper functions
func hexToID(hexStr string) (types.ID, error) {
	if len(hexStr) == 0 {
		return types.ID{}, fmt.Errorf("empty chain ID")
	}
	
	// Handle "0x" prefix
	if len(hexStr) >= 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}
	
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return types.ID{}, err
	}
	
	// Pad or truncate to 32 bytes
	var id types.ID
	copy(id[:], bytes)
	return id, nil
}

func hashBytes(data []byte) [32]byte {
	// Simple hash for demo - in production use proper crypto
	var hash [32]byte
	for i, b := range data {
		hash[i%32] ^= b
	}
	return hash
}