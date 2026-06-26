// Package gpg provides a GPG-based object verifier that checks armored
// OpenPGP detached signatures against a keyring.
package gpg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/go-git/go-git/v6/x/plugin"
)

// Sentinel errors.
var (
	// ErrNilKeyRing is returned when the keyring provided is nil.
	ErrNilKeyRing = errors.New("keyring is nil")
	// ErrNilMessage is returned when a nil message is passed to Verify.
	ErrNilMessage = errors.New("message is nil")
	// ErrMultipleSignatures is returned when the signature carries more than
	// one armored block. Mirrors upstream Git's gpg-interface, which rejects
	// multi-signature payloads because their provenance cannot be reduced to a
	// single authoritative signer.
	ErrMultipleSignatures = errors.New("multiple signatures")
)

// FromKeyRing creates a GPG verifier that checks armored OpenPGP detached
// signatures against the provided keyring. On success the returned
// plugin.Verification carries the signing key fingerprint in Signer and the
// *openpgp.Entity in Details.
//
//nolint:revive // returning unexported *verifier is intentional; callers use it via interface inference
func FromKeyRing(keyring openpgp.EntityList) (*verifier, error) {
	if keyring == nil {
		return nil, ErrNilKeyRing
	}

	return &verifier{keyring: keyring}, nil
}

type verifier struct {
	keyring openpgp.EntityList
}

// Verify reads message and checks signature against the verifier's keyring.
// The context is accepted for interface uniformity across verifiers; OpenPGP
// verification is purely local and does not consult it.
func (v *verifier) Verify(_ context.Context, message io.Reader, signature []byte) (*plugin.Verification, error) {
	if message == nil {
		return nil, ErrNilMessage
	}

	if countSignatureBlocks(signature) > 1 {
		return nil, ErrMultipleSignatures
	}

	entity, err := openpgp.CheckArmoredDetachedSignature(
		v.keyring, message, bytes.NewReader(signature), nil)
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	return &plugin.Verification{
		Signer:  fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint),
		Method:  plugin.SignatureTypeOpenPGP,
		Details: entity,
	}, nil
}

// countSignatureBlocks reports how many OpenPGP signature blocks start at a
// line boundary in data.
func countSignatureBlocks(data []byte) int {
	// begins are the armored headers that start an OpenPGP signature.
	begins := [][]byte{
		[]byte("-----BEGIN PGP SIGNATURE-----"),
		[]byte("-----BEGIN PGP MESSAGE-----"),
	}

	pos, count := 0, 0
	for pos < len(data) {
		for _, begin := range begins {
			if bytes.HasPrefix(data[pos:], begin) {
				count++

				break
			}
		}

		eol := bytes.IndexByte(data[pos:], '\n')
		if eol < 0 {
			break
		}

		pos += eol + 1
	}

	return count
}
