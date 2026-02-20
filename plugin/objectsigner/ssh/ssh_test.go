package ssh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/hiddeco/sshsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/go-git/x/plugin/objectsigner/ssh"
)

func TestFromKey(t *testing.T) {
	t.Parallel()

	sshSigner := generateTestSigner(t)

	tests := []struct {
		signer  gossh.Signer
		wantErr string
		name    string
		algo    ssh.HashAlgorithm
	}{
		{name: "SHA256", signer: sshSigner, algo: ssh.SHA256, wantErr: ""},
		{name: "SHA512", signer: sshSigner, algo: ssh.SHA512, wantErr: ""},
		{name: "nil signer", signer: nil, algo: ssh.SHA512, wantErr: "signer is nil"},
		{name: "invalid algorithm", signer: sshSigner, algo: "invalid", wantErr: "unsupported hash algorithm"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			signer, err := ssh.FromKey(test.signer, ssh.WithHashAlgorithm(test.algo))
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				require.Nil(t, signer)
			} else {
				require.NoError(t, err)
				require.NotNil(t, signer)
			}
		})
	}
}

func TestSign(t *testing.T) {
	t.Parallel()

	sshSigner := generateTestSigner(t)

	tests := []struct {
		message io.Reader
		wantErr string
		name    string
		algo    ssh.HashAlgorithm
	}{
		{name: "SHA512", algo: ssh.SHA512, message: strings.NewReader("signed commit message\n"), wantErr: ""},
		{name: "SHA256", algo: ssh.SHA256, message: strings.NewReader("test message"), wantErr: ""},
		{name: "nil message", algo: ssh.SHA512, message: nil, wantErr: "message is nil"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			signer, err := ssh.FromKey(sshSigner, ssh.WithHashAlgorithm(test.algo))
			require.NoError(t, err)

			sig, err := signer.Sign(test.message)
			if test.wantErr == "" {
				require.NoError(t, err)
				assert.NotEmpty(t, sig)
				assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
				assert.Contains(t, string(sig), "-----END SSH SIGNATURE-----")
			} else {
				require.ErrorContains(t, err, test.wantErr)
				assert.Empty(t, sig)
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	algo := ssh.SHA256
	key := generateTestSigner(t)
	signer, err := ssh.FromKey(key, ssh.WithHashAlgorithm(algo))
	require.NoError(t, err)

	message := "signed commit message\n"

	sig, err := signer.Sign(strings.NewReader(message))
	require.NoError(t, err)

	ssig, err := sshsig.Unarmor(sig)
	require.NoError(t, err)

	err = sshsig.Verify(strings.NewReader(message),
		ssig, key.PublicKey(), algo, "git")
	require.NoError(t, err, "signature verification failed")
}

func TestSignDifferentMessagesProduceDifferentSignatures(t *testing.T) {
	t.Parallel()

	sshSigner := generateTestSigner(t)
	signer, err := ssh.FromKey(sshSigner)
	require.NoError(t, err)

	sig1, err := signer.Sign(strings.NewReader("message one"))
	require.NoError(t, err)

	sig2, err := signer.Sign(strings.NewReader("message two"))
	require.NoError(t, err)

	assert.NotEqual(t, sig1, sig2, "different messages produced identical signatures")
}

//nolint:ireturn // gossh.NewSignerFromKey returns gossh.Signer (interface); no concrete type is accessible
func generateTestSigner(t *testing.T) gossh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generating ed25519 key")

	signer, err := gossh.NewSignerFromKey(priv)
	require.NoError(t, err, "creating SSH signer")

	return signer
}
