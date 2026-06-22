package gpg_test

import (
	"context"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/go-git/x/plugin/objectsigner/gpg"
)

func ExampleFromKey() {
	// Generate a test key. In practice this would be read from an armored file.
	key, err := openpgp.NewEntity("Test User", "", "test@example.com", nil)
	if err != nil {
		panic(err)
	}

	signer, err := gpg.FromKey(key)
	if err != nil {
		panic(err)
	}

	sig, err := signer.Sign(context.Background(), strings.NewReader("signed commit message\n"))
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.Contains(string(sig), "-----BEGIN PGP SIGNATURE-----"))
	fmt.Println(strings.Contains(string(sig), "-----END PGP SIGNATURE-----"))
	// Output:
	// true
	// true
}
