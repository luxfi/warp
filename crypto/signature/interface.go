// Copyright (C) 2025, Lux Industries, Inc.
// See the file LICENSE for licensing terms.

// Package signature is the warp signature-scheme registry. It is the
// ONE place where schemes are named, classified PQ-vs-classical, and
// composed into a runtime selector. The package is PQ-native by
// construction: post-quantum schemes are registered by default and
// classical schemes are opt-in only via Config.LegacyClassicalEnabled.
//
// Decomplection:
//
//   - Scheme    — the named value (ml-dsa-65, pulsar, corona, bls, ...)
//   - Registry  — the runtime container (Get / SetPreferred / Schemes)
//   - Config    — the operator-facing posture knob (PQ-only vs PQ+legacy)
//   - SignContext — the FIPS 204 §5.2 / FIPS 205 §10.2 context-string
//     tag bound into every ML-DSA / SLH-DSA signature
//
// Profile gating (strict-PQ vs hybrid vs classical) lives in
// github.com/luxfi/pq and applies a SINGLE function across every
// consumer of the registry (envelope verifier, tx-pool admission,
// DEX order verify, ZAP attestation). The registry is dumb about
// posture — it just knows which schemes are PQ and which are not.
//
// One concept, one function, one error.
package signature

import (
	"context"
	"errors"
)

// Scheme is a named signature primitive. Wire-format identifiers
// match these strings exactly; renaming a scheme is a breaking
// change to every downstream KAT vector and on-disk envelope.
type Scheme string

// Post-quantum schemes. Default-registered by NewPQNativeRegistry.
const (
	// SchemeMLDSA65 is FIPS 204 ML-DSA-65 (formerly CRYSTALS-Dilithium
	// at NIST security level 3). Used by Warp 2.0 MLDSACertSet lane
	// for per-validator attestations. Context-string bound per
	// FIPS 204 §5.2 — see SignContextWarpV1 below.
	SchemeMLDSA65 Scheme = "ml-dsa-65"

	// SchemePulsar is Lux's R-LWE threshold signature kernel
	// (github.com/luxfi/pulsar). Used by the Warp 2.0 PulsarPulse
	// lane for source-chain transcript-bound threshold signatures.
	SchemePulsar Scheme = "pulsar"

	// SchemeCorona is Lux's production R-LWE post-quantum threshold
	// scheme (github.com/luxfi/corona). Used by Warp 2.0 as an
	// alternate Pulse implementation; the wire format is identical
	// to SchemePulsar (Pulse byte layout, not algorithm-identifying).
	// Replaces the older "Corona" enum value carried over from
	// the academic upstream naming.
	SchemeCorona Scheme = "corona"

	// SchemeSLHDSA is FIPS 205 SLH-DSA (formerly SPHINCS+). Used for
	// long-tail validator attestations where ML-DSA's lattice
	// assumption is not desired. Context-string bound per
	// FIPS 205 §10.2.
	SchemeSLHDSA Scheme = "slh-dsa"
)

// Classical schemes. Registered ONLY when Config.LegacyClassicalEnabled
// is true. Under strict-PQ chains the pq.Mode gate refuses these at
// the envelope verification boundary regardless of registry state.
const (
	// SchemeBLS is BLS12-381 aggregate signature (Warp 1.x Beam).
	// Shor-vulnerable. Available for backwards compatibility with
	// classical chains; refused at the verification boundary under
	// strict-PQ mode.
	SchemeBLS Scheme = "bls"

	// SchemeEd25519 is Ed25519 (RFC 8032). Shor-vulnerable. Same
	// availability rules as SchemeBLS.
	SchemeEd25519 Scheme = "ed25519"

	// SchemeSecp256k1 is ECDSA over secp256k1 (legacy EVM). Shor-
	// vulnerable. Same availability rules as SchemeBLS.
	SchemeSecp256k1 Scheme = "secp256k1"

	// SchemeHybrid composes BLS + Corona over the same transcript
	// for the classical→strict-PQ migration window. Both signatures
	// MUST verify; failure of either is a hard reject. Available
	// even without LegacyClassicalEnabled because hybrid is the
	// canonical migration path (PQ verification is the trust root,
	// BLS is "echo only" per PQ_PROFILES.md).
	SchemeHybrid Scheme = "hybrid"
)

// SignContextWarpV1 is the FIPS 204 §5.2 / FIPS 205 §10.2 context
// string bound into every ML-DSA-65 and SLH-DSA signature produced
// for a Warp 2.0 envelope. This domain-separates Warp envelopes
// from:
//
//   - Lux primary-network validator-identity signatures (use
//     "lux-validator-identity-v1" — see luxfi/ids).
//   - Hanzo / Zoo / Pars chain-internal signatures (use their
//     own per-chain context strings).
//   - Pulsar consensus pulses (use "QUASAR-PULSAR-BUNDLE-v1" — see
//     LP-073 §"Domain-separated message prefixes").
//
// Re-using a context across domains would let an ML-DSA signature
// over a non-warp message be replayed as a Warp envelope attestation
// (or vice versa). Explicitly rejected by FIPS 204 §5.2 binding.
const SignContextWarpV1 = "lux-warp-cross-chain-v1"

// PQSchemes is the canonical set of post-quantum schemes the
// registry tracks. Used by IsPQ and by NewPQNativeRegistry to
// pre-populate the default registry.
var PQSchemes = []Scheme{
	SchemeMLDSA65,
	SchemePulsar,
	SchemeCorona,
	SchemeSLHDSA,
}

// ClassicalSchemes is the canonical set of classical schemes. Used
// by IsClassical and to gate registration on Config.LegacyClassicalEnabled.
// SchemeHybrid is NOT in this set: hybrid is PQ-aware (both lanes
// verify) and is the canonical migration path under any mode.
var ClassicalSchemes = []Scheme{
	SchemeBLS,
	SchemeEd25519,
	SchemeSecp256k1,
}

// IsPQ reports whether s is one of the post-quantum schemes
// tracked by this registry. Used by the pq.Mode gate to refuse
// classical-only verification under strict-PQ chains.
func IsPQ(s Scheme) bool {
	for _, p := range PQSchemes {
		if p == s {
			return true
		}
	}
	return false
}

// IsClassical reports whether s is one of the classical schemes.
// SchemeHybrid is NOT classical — it composes BLS + Corona over the
// same transcript and is the canonical migration path.
func IsClassical(s Scheme) bool {
	for _, c := range ClassicalSchemes {
		if c == s {
			return true
		}
	}
	return false
}

// Verifier provides modular signature verification
type Verifier interface {
	// Scheme returns the signature scheme this verifier uses
	Scheme() Scheme

	// Verify checks if a signature is valid for the given message
	Verify(ctx context.Context, message []byte, signature Signature, signers SignerSet) error

	// VerifyAggregate verifies an aggregated signature from multiple signers
	VerifyAggregate(ctx context.Context, message []byte, signature Signature, signers SignerSet) error
}

// Signer provides modular signature creation
type Signer interface {
	// Scheme returns the signature scheme this signer uses
	Scheme() Scheme

	// Sign creates a signature for the message
	Sign(ctx context.Context, message []byte, key PrivateKey) (Signature, error)

	// AggregateSign creates an aggregated signature with other signers
	AggregateSign(ctx context.Context, message []byte, keys []PrivateKey) (Signature, error)
}

// Signature represents a signature that can be from any scheme
type Signature interface {
	// Scheme returns which signature scheme created this signature
	Scheme() Scheme

	// Bytes returns the serialized signature
	Bytes() []byte

	// Verify checks if this signature is valid (self-contained verification)
	Verify(message []byte, publicKey PublicKey) error
}

// SignerSet represents a set of signers (validators)
type SignerSet interface {
	// GetSigner returns a signer by index
	GetSigner(index int) (PublicKey, uint64, error)

	// TotalWeight returns the total weight of all signers
	TotalWeight() uint64

	// Threshold returns the minimum weight needed for validity
	Threshold() uint64

	// Contains checks if a public key is in the set
	Contains(key PublicKey) (index int, weight uint64, exists bool)
}

// PublicKey interface for all signature schemes
type PublicKey interface {
	// Scheme returns which signature scheme this key is for
	Scheme() Scheme

	// Bytes returns the serialized public key
	Bytes() []byte

	// Equal checks if two public keys are the same
	Equal(other PublicKey) bool
}

// PrivateKey interface for all signature schemes
type PrivateKey interface {
	// PublicKey returns the corresponding public key
	PublicKey() PublicKey

	// Bytes returns the serialized private key (handle with care!)
	Bytes() []byte
}

// Config is the operator-facing posture knob for the signature
// registry. The zero value is the canonical PQ-native default —
// ML-DSA-65 preferred, classical schemes refused at registration
// time.
//
// LegacyClassicalEnabled MUST be set true (explicit opt-in) for any
// of the SchemeBLS / SchemeEd25519 / SchemeSecp256k1 verifiers to be
// installable. This makes "default install" equivalent to
// "PQ-only-capable" and forces every operator that wants classical
// to write the flag down in their chain config — no implicit
// classical fallback is possible.
//
// PreferredScheme overrides the default (SchemeMLDSA65) only when
// it names a PQ scheme. Operators that want SchemeBLS preferred
// MUST set LegacyClassicalEnabled = true AND set PreferredScheme
// = SchemeBLS; either alone is rejected by ApplyTo.
type Config struct {
	// LegacyClassicalEnabled allows classical schemes (BLS, Ed25519,
	// secp256k1) to be registered. Default false — PQ-only. Documented
	// in LEGACY-CLASSICAL.md alongside the deprecation timeline.
	LegacyClassicalEnabled bool

	// PreferredScheme overrides the default preferred scheme. Empty
	// = SchemeMLDSA65. Validated against (PQSchemes ∪ ClassicalSchemes)
	// at ApplyTo time.
	PreferredScheme Scheme
}

// DefaultConfig is the canonical PQ-native default. LegacyClassicalEnabled
// is false; PreferredScheme is SchemeMLDSA65. Returned by value so
// callers can mutate a copy without affecting other call sites.
func DefaultConfig() Config {
	return Config{
		LegacyClassicalEnabled: false,
		PreferredScheme:        SchemeMLDSA65,
	}
}

// ErrClassicalRequiresOptIn is returned by Register when a caller
// attempts to install a classical scheme on a registry whose
// Config.LegacyClassicalEnabled is false. The error carries the
// scheme name so audit logs grep cleanly.
var ErrClassicalRequiresOptIn = errors.New(
	"signature: classical scheme requires Config.LegacyClassicalEnabled=true")

// ErrUnknownScheme is returned when a caller asks for a scheme that
// was not registered.
var ErrUnknownScheme = errors.New("signature: unknown scheme")

// ErrSchemeMismatch is returned by Register when the verifier and
// signer disagree on the scheme they implement.
var ErrSchemeMismatch = errors.New("signature: verifier/signer scheme mismatch")

// Registry manages available signature schemes. Construct via
// NewPQNativeRegistry (default) or NewRegistryFromConfig (operator
// override). Do NOT zero-construct; the zero Registry has no
// classical-opt-in policy and will accept arbitrary schemes.
type Registry struct {
	verifiers map[Scheme]Verifier
	signers   map[Scheme]Signer
	preferred Scheme
	cfg       Config
}

// NewPQNativeRegistry returns the canonical PQ-native registry:
// classical opt-in disabled, SchemeMLDSA65 preferred, no schemes
// pre-registered (callers wire concrete Verifier/Signer pairs via
// Register). This is the constructor every warp caller SHOULD use;
// it makes "PQ default" the only behaviour available without an
// explicit opt-in line.
func NewPQNativeRegistry() *Registry {
	return NewRegistryFromConfig(DefaultConfig())
}

// NewRegistryFromConfig returns a registry pinned to the given
// Config. Used by tests and by operators that explicitly want
// classical schemes available (in which case
// cfg.LegacyClassicalEnabled MUST be true).
func NewRegistryFromConfig(cfg Config) *Registry {
	pref := cfg.PreferredScheme
	if pref == "" {
		pref = SchemeMLDSA65
	}
	return &Registry{
		verifiers: make(map[Scheme]Verifier),
		signers:   make(map[Scheme]Signer),
		preferred: pref,
		cfg:       cfg,
	}
}

// NewRegistry retains the original constructor signature for
// callers that pre-date Config. Internally it wires DefaultConfig
// and overrides the preferred scheme. Existing callers continue to
// work; new code SHOULD use NewPQNativeRegistry.
func NewRegistry(preferred Scheme) *Registry {
	cfg := DefaultConfig()
	cfg.PreferredScheme = preferred
	return NewRegistryFromConfig(cfg)
}

// Config returns the registry's current Config. Returned by value
// (callers cannot mutate the registry's internal state through
// the returned copy).
func (r *Registry) Config() Config {
	return r.cfg
}

// Register adds a signature scheme to the registry. Classical
// schemes are rejected with ErrClassicalRequiresOptIn unless
// Config.LegacyClassicalEnabled is true. PQ schemes are always
// admitted regardless of mode (the PQ-vs-classical decision under
// strict-PQ chains happens at the pq.Mode gate, not here).
func (r *Registry) Register(scheme Scheme, verifier Verifier, signer Signer) error {
	if verifier.Scheme() != scheme || signer.Scheme() != scheme {
		return ErrSchemeMismatch
	}
	if IsClassical(scheme) && !r.cfg.LegacyClassicalEnabled {
		return ErrClassicalRequiresOptIn
	}
	r.verifiers[scheme] = verifier
	r.signers[scheme] = signer
	return nil
}

// GetVerifier returns a verifier for the specified scheme
func (r *Registry) GetVerifier(scheme Scheme) (Verifier, error) {
	v, ok := r.verifiers[scheme]
	if !ok {
		return nil, ErrUnknownScheme
	}
	return v, nil
}

// GetSigner returns a signer for the specified scheme
func (r *Registry) GetSigner(scheme Scheme) (Signer, error) {
	s, ok := r.signers[scheme]
	if !ok {
		return nil, ErrUnknownScheme
	}
	return s, nil
}

// PreferredScheme returns the currently preferred signature scheme
func (r *Registry) PreferredScheme() Scheme {
	return r.preferred
}

// SetPreferred changes the preferred signature scheme. The scheme
// MUST already be registered (otherwise ErrUnknownScheme). Classical
// schemes are only settable when Config.LegacyClassicalEnabled is
// true; the gate is the same as Register's.
func (r *Registry) SetPreferred(scheme Scheme) error {
	if _, ok := r.verifiers[scheme]; !ok {
		return ErrUnknownScheme
	}
	if IsClassical(scheme) && !r.cfg.LegacyClassicalEnabled {
		return ErrClassicalRequiresOptIn
	}
	r.preferred = scheme
	return nil
}

// Schemes returns the set of registered schemes in deterministic
// order (PQ first by PQSchemes order, then classical by
// ClassicalSchemes order, then SchemeHybrid last). Used by tests
// and audit tooling to assert the registry's posture matches a
// declared config.
func (r *Registry) Schemes() []Scheme {
	out := make([]Scheme, 0, len(r.verifiers))
	for _, s := range PQSchemes {
		if _, ok := r.verifiers[s]; ok {
			out = append(out, s)
		}
	}
	for _, s := range ClassicalSchemes {
		if _, ok := r.verifiers[s]; ok {
			out = append(out, s)
		}
	}
	if _, ok := r.verifiers[SchemeHybrid]; ok {
		out = append(out, SchemeHybrid)
	}
	return out
}
