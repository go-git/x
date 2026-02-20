package ssh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/go-git/x/plugin/objectsigner/ssh"
)

func ExampleFromKey() {
	// Generate an ed25519 key for demonstration. In practice this would
	// come from a file (via ssh.ParsePrivateKey).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	key, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		panic(err)
	}

	signer, err := ssh.FromKey(key)
	if err != nil {
		panic(err)
	}

	sig, err := signer.Sign(strings.NewReader("signed commit message\n"))
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.Contains(string(sig), "-----BEGIN SSH SIGNATURE-----"))
	fmt.Println(strings.Contains(string(sig), "-----END SSH SIGNATURE-----"))
	// Output:
	// true
	// true
}
