// Package gpg provides a GPG-based object signer for creating armored
// detached signatures using OpenPGP keys.
package gpg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Sentinel errors.
var (
	// ErrNilSigner is returned when the key provided is nil.
	ErrNilSigner = errors.New("signer is nil")
	// ErrNilMessage is returned when a nil message is passed to Sign.
	ErrNilMessage = errors.New("message is nil")
)

// FromKey creates a new GPG signer that uses the provided OpenPGP entity
// to produce armored detached signatures.
//
//nolint:revive // returning unexported *signer is intentional; callers use it via interface inference
func FromKey(key *openpgp.Entity) (*signer, error) {
	if key == nil {
		return nil, ErrNilSigner
	}

	return &signer{key: key}, nil
}

type signer struct {
	key *openpgp.Entity
}

// Sign reads message and returns an ASCII-armored detached GPG
// signature created with the signer's OpenPGP key. The context is accepted
// for interface uniformity across signers; native OpenPGP signing is purely
// local and does not consult it.
func (s *signer) Sign(_ context.Context, message io.Reader) ([]byte, error) {
	if message == nil {
		return nil, ErrNilMessage
	}

	var buf bytes.Buffer

	err := openpgp.ArmoredDetachSign(&buf, s.key, message, nil)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return buf.Bytes(), nil
}
