package gpg_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-git/x/plugin/objectsigner/gpg"
)

func TestFromKey(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)

	tests := []struct {
		key     *openpgp.Entity
		wantErr error
		name    string
	}{
		{name: "valid key", key: key, wantErr: nil},
		{name: "nil key", key: nil, wantErr: gpg.ErrNilSigner},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			signer, err := gpg.FromKey(test.key)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
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

	tests := []struct {
		message io.Reader
		wantErr string
		name    string
	}{
		{name: "valid message", message: strings.NewReader("signed commit message\n"), wantErr: ""},
		{name: "nil message", message: nil, wantErr: "message is nil"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			signer, err := gpg.FromKey(generateTestKey(t))
			require.NoError(t, err)

			sig, err := signer.Sign(context.Background(), test.message)
			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				require.Nil(t, sig)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, sig)
				assert.Contains(t, string(sig), "-----BEGIN PGP SIGNATURE-----")
				assert.Contains(t, string(sig), "-----END PGP SIGNATURE-----")
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)
	signer, err := gpg.FromKey(key)
	require.NoError(t, err)

	message := "signed commit message\n"

	sig, err := signer.Sign(context.Background(), strings.NewReader(message))
	require.NoError(t, err)

	keyring := openpgp.EntityList{key}
	entity, err := openpgp.CheckArmoredDetachedSignature(
		keyring,
		strings.NewReader(message),
		bytes.NewReader(sig),
		nil,
	)
	require.NoError(t, err, "signature verification failed")
	assert.NotNil(t, entity)
}

func TestSignDifferentMessagesProduceDifferentSignatures(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)
	signer, err := gpg.FromKey(key)
	require.NoError(t, err)

	sig1, err := signer.Sign(context.Background(), strings.NewReader("message one"))
	require.NoError(t, err)

	sig2, err := signer.Sign(context.Background(), strings.NewReader("message two"))
	require.NoError(t, err)

	assert.NotEqual(t, sig1, sig2, "different messages produced identical signatures")
}

func generateTestKey(t *testing.T) *openpgp.Entity {
	t.Helper()

	entity, err := openpgp.NewEntity("Test User", "", "test@example.com", nil)
	require.NoError(t, err, "generating test key")

	return entity
}
