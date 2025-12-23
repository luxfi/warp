// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"testing"
)

func TestSignatureRequestMarshal(t *testing.T) {
	req := &SignatureRequest{
		Message:       []byte("test message"),
		Justification: []byte("justification"),
	}

	data, err := MarshalSignatureRequest(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	decoded, err := UnmarshalSignatureRequest(data)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if string(decoded.Message) != string(req.Message) {
		t.Errorf("message mismatch: expected %s, got %s", req.Message, decoded.Message)
	}
	if string(decoded.Justification) != string(req.Justification) {
		t.Errorf("justification mismatch: expected %s, got %s", req.Justification, decoded.Justification)
	}
}

func TestSignatureResponseMarshal(t *testing.T) {
	signature := []byte("test signature bytes")

	data, err := MarshalSignatureResponse(signature)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	decoded, err := UnmarshalSignatureResponse(data)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if string(decoded.Signature) != string(signature) {
		t.Errorf("signature mismatch: expected %s, got %s", signature, decoded.Signature)
	}
}

func TestSignatureUnmarshalErrors(t *testing.T) {
	// Test empty data
	_, err := UnmarshalSignatureRequest(nil)
	if err == nil {
		t.Error("expected error for nil data")
	}

	_, err = UnmarshalSignatureRequest([]byte{0, 0, 0})
	if err == nil {
		t.Error("expected error for short data")
	}

	_, err = UnmarshalSignatureResponse(nil)
	if err == nil {
		t.Error("expected error for nil data")
	}

	_, err = UnmarshalSignatureResponse([]byte{0, 0, 0})
	if err == nil {
		t.Error("expected error for short data")
	}
}
