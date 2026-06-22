// Package ssh provides an SSH-based object signer for creating armored
// SSH signatures using the sshsig protocol, as defined at:
// https://github.com/openssh/openssh-portable/blob/V_10_2/PROTOCOL.sshsig
package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/hiddeco/sshsig"
	gossh "golang.org/x/crypto/ssh"
)

const (
	// namespace is the sshsig namespace used for git object signing.
	namespace = "git"

	// SHA512 is the SHA-512 hash algorithm.
	SHA512 HashAlgorithm = sshsig.HashSHA512
	// SHA256 is the SHA-256 hash algorithm.
	SHA256 HashAlgorithm = sshsig.HashSHA256
)

// HashAlgorithm is the hash algorithm used when creating SSH signatures.
// This is an alias for sshsig.HashAlgorithm.
type HashAlgorithm = sshsig.HashAlgorithm

// Sentinel errors.
var (
	// ErrNilSigner is returned when the [Signer] provided is nil.
	ErrNilSigner = errors.New("signer is nil")
	// ErrNilMessage is returned when a nil message is passed to Sign.
	ErrNilMessage = errors.New("message is nil")
	// ErrUnsupportedHashAlgorithm is returned when an unsupported [HashAlgorithm] is used.
	ErrUnsupportedHashAlgorithm = errors.New("unsupported hash algorithm")
)

// FromKey creates a new SSH signer that uses the provided ssh.Signer and
// hash algorithm to produce armored SSH signatures.
//
//nolint:revive // returning unexported *signer is intentional; callers use it opaquely
func FromKey(sshSigner gossh.Signer, opts ...Option) (*signer, error) {
	if sshSigner == nil {
		return nil, ErrNilSigner
	}

	cfg := &options{
		algorithm: SHA512,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	switch cfg.algorithm {
	case SHA256, SHA512:
	default:
		return nil, fmt.Errorf("%w: %q",
			ErrUnsupportedHashAlgorithm, string(cfg.algorithm))
	}

	return &signer{signer: sshSigner, algorithm: cfg.algorithm}, nil
}

type signer struct {
	signer    gossh.Signer
	algorithm HashAlgorithm
}

// Sign reads the message from r and returns an armored SSH signature created
// with the signer's SSH key and hash algorithm.
// The signature uses the "git" namespace. The context is accepted for
// interface uniformity across signers; SSH signing is purely local and does
// not consult it.
func (s *signer) Sign(_ context.Context, message io.Reader) ([]byte, error) {
	if message == nil {
		return nil, ErrNilMessage
	}

	sig, err := sshsig.Sign(message, s.signer, s.algorithm, namespace)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return sshsig.Armor(sig), nil
}

// KeyID returns the SHA256 fingerprint of the signer's SSH public key,
// in the form "SHA256:...".
func (s *signer) KeyID() string {
	return gossh.FingerprintSHA256(s.signer.PublicKey())
}
