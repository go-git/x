// Package ssh provides an SSH-based object verifier that checks armored SSH
// signatures using the sshsig protocol, as defined at:
// https://github.com/openssh/openssh-portable/blob/V_10_2/PROTOCOL.sshsig
package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/hiddeco/sshsig"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-git/go-git/v6/x/plugin"
)

// namespace is the sshsig namespace used for git object signing.
const namespace = "git"

// Sentinel errors.
var (
	// ErrNilKey is returned when the public key provided is nil.
	ErrNilKey = errors.New("public key is nil")
	// ErrNilMessage is returned when a nil message is passed to Verify.
	ErrNilMessage = errors.New("message is nil")
)

// FromKey creates an SSH verifier that checks armored SSH signatures against
// the provided trusted public key, in the "git" namespace. On success the
// returned plugin.Verification carries the key's SHA256 fingerprint in Signer
// and the ssh.PublicKey in Details.
//
//nolint:revive // returning unexported *verifier is intentional; callers use it via interface inference
func FromKey(pub gossh.PublicKey) (*verifier, error) {
	if pub == nil {
		return nil, ErrNilKey
	}

	return &verifier{pub: pub}, nil
}

type verifier struct {
	pub gossh.PublicKey
}

// Verify reads message and checks the armored SSH signature against the
// verifier's trusted public key. The hash algorithm is taken from the
// signature. The context is accepted for interface uniformity across
// verifiers; SSH verification is purely local and does not consult it.
func (v *verifier) Verify(_ context.Context, message io.Reader, signature []byte) (*plugin.Verification, error) {
	if message == nil {
		return nil, ErrNilMessage
	}

	sig, err := sshsig.Unarmor(signature)
	if err != nil {
		return nil, fmt.Errorf("parsing signature: %w", err)
	}

	err = sshsig.Verify(message, sig, v.pub, sig.HashAlgorithm, namespace)
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	return &plugin.Verification{
		Signer:  gossh.FingerprintSHA256(v.pub),
		Method:  plugin.SignatureTypeSSH,
		Details: v.pub,
	}, nil
}
