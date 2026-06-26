package gpg_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-git/go-git/v6/x/plugin"

	"github.com/go-git/x/plugin/objectverifier/gpg"
)

// message and signature are the byte-exact payload and detached signature of a
// real tag object produced by upstream git. The signature covers message
// verbatim (the tag bytes with the trailing signature block removed).
const message = `object f6685df0aac4b5adf9eeb760e6d447145c5d0b56
type commit
tag v1.5
tagger Máximo Cuadros <mcuadros@gmail.com> 1618566233 +0200

signed tag
`

const signature = `-----BEGIN PGP SIGNATURE-----

iQGzBAABCAAdFiEE/h5sbbqJFh9j1AdUSqtFFGopTmwFAmB5XFkACgkQSqtFFGop
TmxvgAv+IPjX5WCLFUIMx8hquMZp1VkhQrseE7rljUYaYpga8gZ9s4kseTGhy7Un
61U3Ro6cTPEiQF/FkAGzSdPuGqv0ARBqHDX2tUI9+Zs/K8aG8tN+JTaof0gBcTyI
BLbZVYDTxbS9whxSDewQd0OvBG1m9ISLUhjXo6mbaVvrKXNXTHg40MPZ8ZxjR/vN
hxXXoUVnFyEDo+v6nK56mYtapThDaQQHHzD6D3VaCq3Msog7qAh9/ZNBmgb88aQ3
FoK8PHMyr5elsV3mE9bciZBUc+dtzjOvp94uQ5ZKUXaPusXaYXnKpVnzhyer6RBI
gJLWtPwAinqmN41rGJ8jDAGrpPNjaRrMhGtbyVUPUf19OxuUIroe77sIIKTP0X2o
Wgp56dYpTst0JcGv/FYCeau/4pTRDfwHAOcDiBQ/0ag9IrZp9P8P9zlKmzNPEraV
pAe1/EFuhv2UDLucAiWM8iDZIcw8iN0OYMOGUmnk0WuGIo7dzLeqMGY+ND5n5Z8J
sZC//k6m
=VhHy
-----END PGP SIGNATURE-----
`

const keyRing = `
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=oYTT
-----END PGP PUBLIC KEY BLOCK-----
`

func testKeyRing(t *testing.T) openpgp.EntityList {
	t.Helper()

	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(keyRing))
	require.NoError(t, err)

	return el
}

func TestFromKeyRing(t *testing.T) {
	t.Parallel()

	verifier, err := gpg.FromKeyRing(nil)
	require.ErrorIs(t, err, gpg.ErrNilKeyRing)
	require.Nil(t, verifier)

	verifier, err = gpg.FromKeyRing(testKeyRing(t))
	require.NoError(t, err)
	require.NotNil(t, verifier)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	verifier, err := gpg.FromKeyRing(testKeyRing(t))
	require.NoError(t, err)

	got, err := verifier.Verify(context.Background(), strings.NewReader(message), []byte(signature))
	require.NoError(t, err)

	assert.Equal(t, plugin.SignatureTypeOpenPGP, got.Method)
	assert.NotEmpty(t, got.Signer)

	entity, ok := got.Details.(*openpgp.Entity)
	require.True(t, ok, "Details must be an *openpgp.Entity")
	_, ok = entity.Identities["go-git contributor <contributor@go-git.local>"]
	assert.True(t, ok, "verified entity must carry the signing identity")
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	t.Parallel()

	verifier, err := gpg.FromKeyRing(testKeyRing(t))
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), strings.NewReader(message+"tampered"), []byte(signature))
	assert.Error(t, err)
}

func TestVerifyRejectsMultipleSignatures(t *testing.T) {
	t.Parallel()

	verifier, err := gpg.FromKeyRing(testKeyRing(t))
	require.NoError(t, err)

	block := "-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n"
	_, err = verifier.Verify(context.Background(), strings.NewReader(message), []byte(block+block))
	assert.ErrorIs(t, err, gpg.ErrMultipleSignatures)
}

func TestVerifyNilMessage(t *testing.T) {
	t.Parallel()

	verifier, err := gpg.FromKeyRing(testKeyRing(t))
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), nil, []byte(signature))
	assert.ErrorIs(t, err, gpg.ErrNilMessage)
}
