package ssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/hiddeco/sshsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-git/go-git/v6/x/plugin"

	"github.com/go-git/x/plugin/objectverifier/ssh"
)

const message = "signed commit message\n"

//nolint:ireturn // gossh.NewSignerFromSigner returns gossh.Signer (interface); no concrete type is accessible
func generateSigner(t *testing.T) gossh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromSigner(priv)
	require.NoError(t, err)

	return signer
}

func armoredSignature(t *testing.T, signer gossh.Signer, msg string, h sshsig.HashAlgorithm) []byte {
	t.Helper()

	sig, err := sshsig.Sign(strings.NewReader(msg), signer, h, "git")
	require.NoError(t, err)

	return sshsig.Armor(sig)
}

func TestFromKey(t *testing.T) {
	t.Parallel()

	verifier, err := ssh.FromKey(nil)
	require.ErrorIs(t, err, ssh.ErrNilKey)
	require.Nil(t, verifier)

	signer := generateSigner(t)
	verifier, err = ssh.FromKey(signer.PublicKey())
	require.NoError(t, err)
	require.NotNil(t, verifier)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	signer := generateSigner(t)
	verifier, err := ssh.FromKey(signer.PublicKey())
	require.NoError(t, err)

	for _, h := range []sshsig.HashAlgorithm{sshsig.HashSHA256, sshsig.HashSHA512} {
		sig := armoredSignature(t, signer, message, h)

		got, err := verifier.Verify(context.Background(), strings.NewReader(message), sig)
		require.NoError(t, err)

		assert.Equal(t, plugin.SignatureTypeSSH, got.Method)
		assert.Equal(t, gossh.FingerprintSHA256(signer.PublicKey()), got.Signer)
		assert.NotNil(t, got.Details)
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	t.Parallel()

	signer := generateSigner(t)
	sig := armoredSignature(t, signer, message, sshsig.HashSHA512)

	v, err := ssh.FromKey(signer.PublicKey())
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), strings.NewReader(message+"tampered"), sig)
	assert.Error(t, err)
}

func TestVerifyRejectsUntrustedKey(t *testing.T) {
	t.Parallel()

	signer := generateSigner(t)
	sig := armoredSignature(t, signer, message, sshsig.HashSHA512)

	other := generateSigner(t)
	v, err := ssh.FromKey(other.PublicKey())
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), strings.NewReader(message), sig)
	assert.Error(t, err, "signature from an untrusted key must not verify")
}

func TestVerifyNilMessage(t *testing.T) {
	t.Parallel()

	signer := generateSigner(t)
	v, err := ssh.FromKey(signer.PublicKey())
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), nil, []byte("ignored"))
	assert.ErrorIs(t, err, ssh.ErrNilMessage)
}
