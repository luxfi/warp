// Copyright (C) 2025, Lux Industries, Inc.
// See the file LICENSE for licensing terms.

package backend

import (
    "context"
    "github.com/luxfi/warp/types"
)

const SignatureLen = 96 // BLS sig

// Backend defines the interface for Warp message handling
// This interface is designed to be implementable by any blockchain
// through simple precompiles
type Backend interface {
    // Core message operations (required)
    IssueSignature(ctx context.Context, msg []byte) ([]byte, error)
    GetMessage(messageID types.ID) (types.Message, error)
    GetMessageSignature(ctx context.Context, message types.Message) ([]byte, error)
    GetBlockSignature(ctx context.Context, blockID types.ID) ([]byte, error)
    
    // Optional privacy extensions (via Z-Chain FHE)
    // Returns nil if privacy features are not enabled
    GetPrivacyExtension() PrivacyBackend
}

// PrivacyBackend provides optional privacy features via Z-Chain FHE
// Any L1 can implement this through precompiles if they support FHE
type PrivacyBackend interface {
    // EncryptMessage creates a private message using FHE
    EncryptMessage(msg types.Message, recipientKey []byte) ([]byte, error)
    
    // ProcessEncryptedMessage handles encrypted messages without decryption
    ProcessEncryptedMessage(ctx context.Context, encryptedMsg []byte) error
    
    // IsPrivacyEnabled returns true if Z-Chain privacy is available
    IsPrivacyEnabled() bool
}