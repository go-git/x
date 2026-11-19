# knownhosts

Algorithm-aware OpenSSH `known_hosts` handling for SSH clients, including
[go-git](https://github.com/go-git/go-git).

It wraps `golang.org/x/crypto/ssh/knownhosts` and adds:

- The host key algorithms known for a host, for `ssh.ClientConfig.HostKeyAlgorithms`.
  Without them the server may offer a key type that `known_hosts` does not
  list, and the connection fails with a key mismatch.
- `@cert-authority` lines reported as `ssh.CertAlgo*` algorithms.
- `*` wildcard host patterns that also match non-standard ports, as OpenSSH does.
- Helpers to write `known_hosts` lines.

go-git v6 checks `known_hosts` by default through an internal copy of the
parts of this package it needs. Use this module when you need the rest of the
API, or to build the host key callback yourself.

## Usage with go-git

```go
import (
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/client"
	"github.com/go-git/go-git/v6/plumbing/transport/ssh"
	"github.com/go-git/x/ssh/knownhosts"
)

home, err := os.UserHomeDir()
if err != nil {
	return err
}

db, err := knownhosts.NewDB(filepath.Join(home, ".ssh", "known_hosts"))
if err != nil {
	return err
}

auth, err := ssh.NewPublicKeysFromFile("git", filepath.Join(home, ".ssh", "id_ed25519"), "")
if err != nil {
	return err
}
auth.HostKeyCallback = db.HostKeyCallback()
auth.HostKeyAlgorithms = db.HostKeyAlgorithms("github.com:22")

r, err := git.PlainClone("/tmp/repo", &git.CloneOptions{
	URL:           "git@github.com:go-git/go-git.git",
	ClientOptions: []client.Option{client.WithSSHAuth(auth)},
})
if err != nil {
	return err
}
defer func() { _ = r.Close() }()
```

`HostKeyAlgorithms` takes the `host:port` being connected to, so set it per
remote host.

## Upstream

This package is a copy of [github.com/skeema/knownhosts](https://github.com/skeema/knownhosts)
at [v1.3.0](https://github.com/skeema/knownhosts/tree/v1.3.0)
(commit `9485bdec8ed521b32ab0e9310619effa071a99d6`), which go-git vendored
before v6. Changes from upstream are limited to lint fixes.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE), both kept from upstream.
