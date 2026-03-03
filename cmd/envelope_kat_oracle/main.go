// Copyright (c) 2025-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// envelope_kat_oracle — emits byte-equal KAT vectors for the Warp 2.0
// envelope (LP-105 §"Warp evolution"). Drives warp.EnvelopeV2 through
// its canonical RLP serialization plus the version-byte framing.
//
// Wire format (per entry):
//
//	name                       short label
//	network_id                 v1 UnsignedMessage.NetworkID
//	source_chain_id_hex        v1 UnsignedMessage.SourceChainID
//	payload_hex                v1 UnsignedMessage.Payload
//	signers_indices            BitSetSignature signer indices
//	signature_byte             Pattern byte filling the 96-byte BLS sig
//	source_nebula_root_hex     EnvelopeV2.SourceNebulaRoot ([32]byte)
//	source_key_era_id          EnvelopeV2.SourceKeyEraID
//	source_generation          EnvelopeV2.SourceGeneration
//	hash_suite_id              EnvelopeV2.HashSuiteID ("" or "Pulsar-SHA3")
//	pulsar_pulse_byte          Pattern byte filling pulse bytes (0 = absent)
//	pulsar_pulse_len           Pulse byte length
//	mldsa_cert_set_byte        Pattern byte filling cert set bytes (0 = absent)
//	mldsa_cert_set_len         Cert set byte length
//	envelope_wire_hex          Full wire bytes (version byte + RLP body)
//	envelope_wire_sha256       sha256 of envelope_wire_hex (port fingerprint)
//	envelope_id_hex            EnvelopeV2.ID() (= embedded v1 message ID)
//
// Determinism contract: every entry is byte-identical across hosts /
// builds / OSes. Cross-language ports consume (network_id,
// source_chain_id_hex, payload_hex, signers_indices, signature_byte,
// source_nebula_root_hex, source_key_era_id, source_generation,
// hash_suite_id, pulsar_pulse_*, mldsa_cert_set_*) and must reproduce
// envelope_wire_hex bit-for-bit.
//
// Output: scripts/kat/envelope_kat.json (path overridable via
// WARP_ENVELOPE_KAT_PATH or positional arg).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

type Entry struct {
	Name                string `json:"name"`
	NetworkID           uint32 `json:"network_id"`
	SourceChainIDHex    string `json:"source_chain_id_hex"`
	PayloadHex          string `json:"payload_hex"`
	SignersIndices      []int  `json:"signers_indices"`
	SignatureByte       byte   `json:"signature_byte"`
	SourceNebulaRootHex string `json:"source_nebula_root_hex"`
	SourceKeyEraID      uint64 `json:"source_key_era_id"`
	SourceGeneration    uint64 `json:"source_generation"`
	HashSuiteID         string `json:"hash_suite_id"`
	PulsarPulseByte     byte   `json:"pulsar_pulse_byte"`
	PulsarPulseLen      int    `json:"pulsar_pulse_len"`
	MLDSACertSetByte    byte   `json:"mldsa_cert_set_byte"`
	MLDSACertSetLen     int    `json:"mldsa_cert_set_len"`
	EnvelopeWireHex     string `json:"envelope_wire_hex"`
	EnvelopeWireSHA256  string `json:"envelope_wire_sha256"`
	EnvelopeIDHex       string `json:"envelope_id_hex"`
}

type Output struct {
	Spec    string  `json:"spec"`
	Version string  `json:"version"`
	Entries []Entry `json:"entries"`
}

type fixture struct {
	name                string
	networkID           uint32
	sourceChainID       ids.ID
	payload             []byte
	signers             []int
	signatureByte       byte
	sourceNebulaRoot    [32]byte
	sourceKeyEraID      uint64
	sourceGeneration    uint64
	hashSuiteID         string
	pulsarPulseByte     byte
	pulsarPulseLen      int
	mldsaCertSetByte    byte
	mldsaCertSetLen     int
}

func build(f fixture) Entry {
	unsigned, err := warp.NewUnsignedMessage(f.networkID, f.sourceChainID, f.payload)
	if err != nil {
		fail(err)
	}

	sigSet := warp.NewBitSet()
	for _, idx := range f.signers {
		sigSet.Add(idx)
	}
	var sigBytes [bls.SignatureLen]byte
	copy(sigBytes[:], bytes.Repeat([]byte{f.signatureByte}, bls.SignatureLen))
	sig := warp.NewBitSetSignature(sigSet, sigBytes)
	msg, err := warp.NewMessage(unsigned, sig)
	if err != nil {
		fail(err)
	}

	var pulse []byte
	if f.pulsarPulseLen > 0 {
		pulse = bytes.Repeat([]byte{f.pulsarPulseByte}, f.pulsarPulseLen)
	}
	var cert []byte
	if f.mldsaCertSetLen > 0 {
		cert = bytes.Repeat([]byte{f.mldsaCertSetByte}, f.mldsaCertSetLen)
	}

	env := &warp.EnvelopeV2{
		Message:          msg,
		SourceNebulaRoot: f.sourceNebulaRoot,
		SourceKeyEraID:   f.sourceKeyEraID,
		SourceGeneration: f.sourceGeneration,
		HashSuiteID:      f.hashSuiteID,
		PulsarPulse:      pulse,
		MLDSACertSet:     cert,
	}
	if err := env.Verify(); err != nil {
		fail(err)
	}
	wire, err := env.Bytes()
	if err != nil {
		fail(err)
	}
	wireHash := sha256.Sum256(wire)
	id := env.ID()

	return Entry{
		Name:                f.name,
		NetworkID:           f.networkID,
		SourceChainIDHex:    hex.EncodeToString(f.sourceChainID[:]),
		PayloadHex:          hex.EncodeToString(f.payload),
		SignersIndices:      append([]int(nil), f.signers...),
		SignatureByte:       f.signatureByte,
		SourceNebulaRootHex: hex.EncodeToString(f.sourceNebulaRoot[:]),
		SourceKeyEraID:      f.sourceKeyEraID,
		SourceGeneration:    f.sourceGeneration,
		HashSuiteID:         f.hashSuiteID,
		PulsarPulseByte:     f.pulsarPulseByte,
		PulsarPulseLen:      f.pulsarPulseLen,
		MLDSACertSetByte:    f.mldsaCertSetByte,
		MLDSACertSetLen:     f.mldsaCertSetLen,
		EnvelopeWireHex:     hex.EncodeToString(wire),
		EnvelopeWireSHA256:  hex.EncodeToString(wireHash[:]),
		EnvelopeIDHex:       hex.EncodeToString(id[:]),
	}
}

func main() {
	chainA := ids.ID{0xA1, 0xA2, 0xA3, 0xA4}
	chainB := ids.ID{0xB0, 0xB0, 0xB0, 0xB0}
	nebulaA := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}
	nebulaZero := [32]byte{}

	out := Output{
		Spec:    "Warp-2.0-envelope",
		Version: "v1",
	}
	out.Entries = []Entry{
		build(fixture{
			name:                "default-pulse-cert",
			networkID:           1,
			sourceChainID:       chainA,
			payload:             []byte("envelope-test-payload"),
			signers:             []int{0, 2, 4},
			signatureByte:       0xAB,
			sourceNebulaRoot:    nebulaA,
			sourceKeyEraID:      7,
			sourceGeneration:    11,
			hashSuiteID:         warp.DefaultHashSuiteID,
			pulsarPulseByte:     0x42,
			pulsarPulseLen:      64,
			mldsaCertSetByte:    0xC3,
			mldsaCertSetLen:     192,
		}),
		build(fixture{
			name:                "no-pulse-no-cert",
			networkID:           1,
			sourceChainID:       chainA,
			payload:             []byte("envelope-test-payload"),
			signers:             []int{0, 2, 4},
			signatureByte:       0xAB,
			sourceNebulaRoot:    nebulaZero,
			sourceKeyEraID:      0,
			sourceGeneration:    0,
			hashSuiteID:         "",
			pulsarPulseByte:     0,
			pulsarPulseLen:      0,
			mldsaCertSetByte:    0,
			mldsaCertSetLen:     0,
		}),
		build(fixture{
			name:                "pulse-only",
			networkID:           2,
			sourceChainID:       chainB,
			payload:             []byte("pulse-only-payload"),
			signers:             []int{1, 3, 5, 7},
			signatureByte:       0x77,
			sourceNebulaRoot:    nebulaA,
			sourceKeyEraID:      99,
			sourceGeneration:    1,
			hashSuiteID:         warp.DefaultHashSuiteID,
			pulsarPulseByte:     0x33,
			pulsarPulseLen:      96,
			mldsaCertSetByte:    0,
			mldsaCertSetLen:     0,
		}),
		build(fixture{
			name:                "cert-only",
			networkID:           1,
			sourceChainID:       chainA,
			payload:             []byte{},
			signers:             []int{0},
			signatureByte:       0x11,
			sourceNebulaRoot:    nebulaZero,
			sourceKeyEraID:      0,
			sourceGeneration:    0,
			hashSuiteID:         warp.DefaultHashSuiteID,
			pulsarPulseByte:     0,
			pulsarPulseLen:      0,
			mldsaCertSetByte:    0xEE,
			mldsaCertSetLen:     128,
		}),
	}

	outPath := filepath.Join(
		os.Getenv("HOME"), "work", "lux", "warp", "scripts", "kat",
		"envelope_kat.json",
	)
	if env := os.Getenv("WARP_ENVELOPE_KAT_PATH"); env != "" {
		outPath = env
	}
	if len(os.Args) >= 2 {
		outPath = os.Args[1]
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fail(err)
	}
	f, err := os.Create(outPath)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "wrote envelope_kat.json (%d entries) → %s\n",
		len(out.Entries), outPath)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
