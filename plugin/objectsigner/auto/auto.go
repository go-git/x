// Package auto constructs a [Signer] from the git signing configuration
// fields gpg.format and user.signingKey. It supports OpenPGP and SSH signing.
//
// For SSH signing the resolution logic closely mirrors the git CLI: file
// paths, key:: literals, and .pub paths matched via an SSH agent are all
// supported. For OpenPGP signing the behaviour differs from git: the git
// CLI expects a key ID or fingerprint and shells out to gpg(1), whereas
// this package expects a file path to an armored private-key ring and
// signs natively in Go.
//
// The underlying signing process takes place via Go native libraries, as
// opposed to shelling out to binaries.
//
// Passphrase-protected keys are not supported directly. Expose such keys
// through an SSH agent instead, or use the lower-level gpg and ssh sibling
// packages when full control over key loading is required.
package auto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	billy "github.com/go-git/go-billy/v6"
	"github.com/go-git/go-billy/v6/osfs"
	"github.com/go-git/go-billy/v6/util"
	gpgpkg "github.com/go-git/x/plugin/objectsigner/gpg"
	sshpkg "github.com/go-git/x/plugin/objectsigner/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	// ErrPassphraseUnsupported is returned when the SSH private key on disk
	// is protected by a passphrase.
	ErrPassphraseUnsupported = errors.New("passphrase-protected SSH keys are not supported")
	// ErrEncryptedKeyUnsupported is returned when every private key in an
	// OpenPGP key ring is encrypted and no unencrypted alternative exists.
	ErrEncryptedKeyUnsupported = errors.New("encrypted GPG private keys are not supported")
	// ErrNoPrivateKey is returned when no usable private key can be found:
	// the key ring contains no private-key material, or no SigningKey or
	// agent was provided.
	ErrNoPrivateKey = errors.New("no private key found")
	// ErrNoPrivateKeyInAgent is returned when the SSH agent holds no keys.
	ErrNoPrivateKeyInAgent = errors.New("no private key found in SSH agent")
	// ErrUnsupportedFormat is returned for unrecognized signing formats.
	ErrUnsupportedFormat = errors.New("unsupported signing format")
)

// Format represents the signing format as configured by gpg.format.
type Format string

const (
	// FormatOpenPGP selects OpenPGP (GPG) signing. This is the default
	// when no format is configured.
	FormatOpenPGP Format = "openpgp"
	// FormatSSH selects SSH signing.
	FormatSSH Format = "ssh"
)

// Config holds the git signing configuration values needed to construct
// the appropriate signer.
type Config struct {
	// FS is the filesystem used to read key files. When nil, it defaults
	// to the OS root filesystem.
	FS billy.Basic

	// SSHAgent is an optional SSH agent for SSH signing. It is consulted when
	// SigningKey is a key:: literal, a .pub file path, or empty. For any other
	// path, the private key is read from FS directly and the agent is ignored.
	SSHAgent agent.Agent

	// SigningKey is the value of user.signingKey.
	//
	// For SSH format:
	//   - Path to a private key file (e.g. ~/.ssh/id_ed25519).
	//   - Path to a public key file ending in .pub (e.g. ~/.ssh/id_ed25519.pub)
	//     when SSHAgent is set; the agent is queried for the matching signer.
	//   - A key:: literal (e.g. "key::ssh-ed25519 AAAA...") when SSHAgent is
	//     set; the agent is queried for the matching signer.
	//   - Empty string when SSHAgent is set; the first agent signer is used.
	//
	// For OpenPGP format: path to an armored private-key file.
	//
	// A leading ~/ is expanded to the current user's home directory.
	// ~username/ prefixes are not expanded.
	SigningKey string

	// Format is the value of gpg.format.
	// Supported: FormatSSH, FormatOpenPGP. Defaults to FormatOpenPGP when empty.
	Format Format
}

// Signer signs a message read from an io.Reader and returns the raw signature
// bytes. The context cancels signers that perform external or remote work
// (e.g. an external program); purely local signers ignore it.
type Signer interface {
	Sign(ctx context.Context, message io.Reader) ([]byte, error)
}

// FromConfig returns a [Signer] configured according to the provided Config.
// It reads the signing key from disk and selects the appropriate signer
// implementation based on the format.
//
//nolint:ireturn // Signer is the package's own exported interface; callers always use it as Signer.
func FromConfig(cfg Config) (Signer, error) {
	if cfg.FS == nil {
		cfg.FS = osfs.Default
	}

	signingKey, err := expandHome(cfg.SigningKey)
	if err != nil {
		return nil, err
	}

	cfg.SigningKey = signingKey

	switch cfg.Format {
	case FormatSSH:
		return newSSHSigner(cfg.FS, cfg.SigningKey, cfg.SSHAgent)
	case "", FormatOpenPGP:
		return newGPGSigner(cfg.FS, cfg.SigningKey)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, cfg.Format)
	}
}

// expandHome replaces a leading ~/ with the current user's home directory.
// Paths that do not start with ~/ are returned unchanged. ~username/ prefixes
// are not expanded.
func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("expanding ~/ in signing key path: %w", err)
	}

	return filepath.Join(home, path[2:]), nil
}

// newSSHSigner resolves keyInfoOrPath and returns an SSH signer.
// Resolution order:
//
//  1. key:: prefix – keyInfoOrPath holds a literal public key; sshAgent must
//     be non-nil and is queried for the matching signer.
//  2. .pub suffix + sshAgent – the public key is read from fsys and the
//     matching agent signer is returned.
//  3. Any other non-empty path – the file is read from fsys as a private key;
//     sshAgent is not consulted.
//  4. Empty keyInfoOrPath + sshAgent – the first available agent signer is used.
//  5. Empty keyInfoOrPath, no sshAgent – error.
//
//nolint:ireturn // Signer is the package's own exported interface.
func newSSHSigner(fsys billy.Basic, keyInfoOrPath string, sshAgent agent.Agent) (Signer, error) {
	if len(keyInfoOrPath) > 0 {
		return sshSignerFromKey(fsys, keyInfoOrPath, sshAgent)
	}

	// No SigningKey: use the first available key from the agent.
	if sshAgent != nil {
		return sshFromAgent(sshAgent, nil)
	}

	return nil, fmt.Errorf("%w: %s", ErrNoPrivateKey, "missing signingKey or active ssh-agent")
}

// sshSignerFromKey resolves a non-empty keyInfoOrPath to an SSH signer.
//
//nolint:ireturn // Signer is the package's own exported interface.
func sshSignerFromKey(fsys billy.Basic, keyInfoOrPath string, sshAgent agent.Agent) (Signer, error) {
	if key, found := strings.CutPrefix(keyInfoOrPath, "key::"); found {
		return sshSignerFromLiteral(sshAgent, key)
	}

	if strings.HasSuffix(keyInfoOrPath, ".pub") && sshAgent != nil {
		return sshSignerFromPubFile(fsys, keyInfoOrPath, sshAgent)
	}

	// Not a key:: literal or agent-matched .pub path: read as a private key.
	return sshSignerFromPrivateKeyFile(fsys, keyInfoOrPath)
}

// sshSignerFromLiteral resolves a key:: literal against the SSH agent.
//
//nolint:ireturn // Signer is the package's own exported interface.
func sshSignerFromLiteral(sshAgent agent.Agent, key string) (Signer, error) {
	if sshAgent == nil {
		return nil, fmt.Errorf("%w: signingKey must be a file path when ssh-agent is not being used", ErrNoPrivateKey)
	}

	pubKey, err := parseAuthorizedKey([]byte(sshTrimIdentifier(key)))
	if err != nil {
		return nil, fmt.Errorf("parsing SSH public key from signingKey literal: %w", err)
	}

	return sshFromAgent(sshAgent, pubKey.Marshal())
}

// sshSignerFromPubFile reads a .pub file from fsys and matches it against the SSH agent.
//
//nolint:ireturn // Signer is the package's own exported interface.
func sshSignerFromPubFile(fsys billy.Basic, keyInfoOrPath string, sshAgent agent.Agent) (Signer, error) {
	pubData, err := util.ReadFile(fsys, keyInfoOrPath)
	if err != nil {
		return nil, fmt.Errorf("reading SSH public key: %w", err)
	}

	pubKey, err := parseAuthorizedKey(pubData)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH public key: %w", err)
	}

	return sshFromAgent(sshAgent, pubKey.Marshal())
}

// sshSignerFromPrivateKeyFile reads a private key from fsys and returns a signer.
//
//nolint:ireturn // Signer is the package's own exported interface.
func sshSignerFromPrivateKeyFile(fsys billy.Basic, keyInfoOrPath string) (Signer, error) {
	data, err := util.ReadFile(fsys, keyInfoOrPath)
	if err != nil {
		return nil, fmt.Errorf("reading SSH private key: %w", err)
	}

	signer, err := gossh.ParsePrivateKey(data)
	if err != nil {
		var passErr *gossh.PassphraseMissingError
		if errors.As(err, &passErr) {
			return nil, ErrPassphraseUnsupported
		}

		return nil, fmt.Errorf("parsing SSH private key: %w", err)
	}

	result, fErr := sshpkg.FromKey(signer, sshpkg.WithHashAlgorithm(sshpkg.SHA512))
	if fErr != nil {
		return nil, fmt.Errorf("creating SSH signer: %w", fErr)
	}

	return result, nil
}

// parseAuthorizedKey parses a single entry from an authorized_keys file,
// returning only the public key. It wraps gossh.ParseAuthorizedKey,
// discarding the unused return values.
//
//nolint:ireturn // gossh.PublicKey is an external interface; no concrete type is accessible.
func parseAuthorizedKey(data []byte) (gossh.PublicKey, error) {
	//nolint:dogsled // API returns 5 values; only key+err are needed.
	pubKey, _, _, _, err := gossh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing authorized key: %w", err)
	}

	return pubKey, nil
}

// sshAuthorizedKeyFields is the minimum number of space-separated fields in
// an authorized-key string (key-type + base64-encoded key).
const sshAuthorizedKeyFields = 2

// sshTrimIdentifier strips any trailing comment from an authorized-key string,
// returning only the key type and base64-encoded key (e.g.
// "ssh-ed25519 AAAA... comment" → "ssh-ed25519 AAAA...").
func sshTrimIdentifier(key string) string {
	fields := strings.Fields(key)
	if len(fields) < sshAuthorizedKeyFields {
		return key
	}

	return strings.Join(fields[:sshAuthorizedKeyFields], " ")
}

// sshFromAgent returns a Signer backed by the agent signer whose public-key
// wire encoding matches pubKeyBytes. When pubKeyBytes is nil or empty, the
// first available signer is returned without filtering.
//
//nolint:ireturn // Signer is the package's own exported interface.
func sshFromAgent(sshAgent agent.Agent, pubKeyBytes []byte) (Signer, error) {
	signers, err := sshAgent.Signers()
	if err != nil {
		return nil, fmt.Errorf("listing agent signers: %w", err)
	}

	for _, s := range signers {
		if len(pubKeyBytes) == 0 || bytes.Equal(s.PublicKey().Marshal(), pubKeyBytes) {
			signer, sErr := sshpkg.FromKey(s, sshpkg.WithHashAlgorithm(sshpkg.SHA512))
			if sErr != nil {
				return nil, fmt.Errorf("creating SSH signer from agent key: %w", sErr)
			}

			return signer, nil
		}
	}

	if len(pubKeyBytes) != 0 {
		return nil, fmt.Errorf("%w: no keys found matching signingKey", ErrNoPrivateKey)
	}

	return nil, ErrNoPrivateKeyInAgent
}

// newGPGSigner reads an armored OpenPGP private-key ring from keyPath and
// returns a signer backed by the first unencrypted private key found.
// Entities without private-key material are skipped. Encrypted private keys
// are also skipped; ErrEncryptedKeyUnsupported is returned only when no
// unencrypted key exists in the ring.
//
//nolint:ireturn // Signer is the package's own exported interface.
func newGPGSigner(fsys billy.Basic, keyPath string) (Signer, error) {
	if keyPath == "" {
		return nil, fmt.Errorf("%w: %s", ErrNoPrivateKey, "missing signingKey")
	}

	data, err := util.ReadFile(fsys, keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading GPG private key: %w", err)
	}

	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parsing GPG key ring: %w", err)
	}

	var hasEncrypted bool

	for _, entity := range entities {
		if entity.PrivateKey == nil {
			continue
		}

		if entity.PrivateKey.Encrypted {
			hasEncrypted = true

			continue
		}

		signer, sErr := gpgpkg.FromKey(entity)
		if sErr != nil {
			return nil, fmt.Errorf("creating GPG signer: %w", sErr)
		}

		return signer, nil
	}

	if hasEncrypted {
		return nil, ErrEncryptedKeyUnsupported
	}

	return nil, ErrNoPrivateKey
}
