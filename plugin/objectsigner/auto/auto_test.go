package auto_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	billy "github.com/go-git/go-billy/v6"
	"github.com/go-git/go-billy/v6/memfs"
	"github.com/go-git/go-billy/v6/osfs"
	"github.com/hiddeco/sshsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/go-git/x/plugin/objectsigner/auto"
)

func TestFromConfigSSH(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeSSHKey(t, filepath.Join(dir, "id_ed25519"))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "id_ed25519",
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
	assert.Contains(t, string(sig), "-----END SSH SIGNATURE-----")
}

// When no SSH agent is configured, the .pub suffix carries no special meaning:
// the implementation reads the file at the given path directly as a private key.
func TestFromConfigSSHPubSuffixNoAgent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Write a private key to a file whose name ends in .pub.
	writeSSHKey(t, filepath.Join(dir, "id_ed25519.pub"))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "id_ed25519.pub",
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
}

func TestFromConfigSSHPassphraseProtected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "id_ed25519"), pem.EncodeToMemory(block), 0o600))

	_, err = auto.FromConfig(auto.Config{
		SigningKey: "id_ed25519",
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, auto.ErrPassphraseUnsupported)
}

// key:: prefix requires an SSH agent; the literal public key is used to
// select the matching signer from the agent.
func TestFromConfigSSHKeyLiteralAgent(t *testing.T) {
	t.Parallel()

	keyring := agent.NewKeyring()

	// Decoy key — must not be selected.
	addAgentKey(t, keyring, "")

	// Target key.
	targetPub := addAgentKey(t, keyring, "")

	// key:: literal, type + base64 only (no trailing comment or newline).
	literal := "key::" + strings.TrimSpace(string(gossh.MarshalAuthorizedKey(targetPub)))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: literal,
		Format:     auto.FormatSSH,
		FS:         nil,
		SSHAgent:   keyring,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
}

func TestFromConfigSSHKeyLiteralNoAgent(t *testing.T) {
	t.Parallel()

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "key::ssh-ed25519 AAAA...",
		Format:     auto.FormatSSH,
		FS:         nil,
		SSHAgent:   nil,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, auto.ErrNoPrivateKey)
	assert.Contains(t, err.Error(), "signingKey must be a file path")
}

// The .pub path is read from disk, the matching agent signer is returned.
func TestFromConfigSSHAgentPubKeyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyring := agent.NewKeyring()
	addAgentKey(t, keyring, filepath.Join(dir, "id_ed25519.pub"))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "id_ed25519.pub",
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   keyring,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
}

// When the agent holds multiple keys, the .pub path is used to select only
// the matching signer.
func TestFromConfigSSHAgentMultipleKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyring := agent.NewKeyring()

	// Add two decoy keys before the target.
	addAgentKey(t, keyring, "")
	addAgentKey(t, keyring, "")

	// Target key — its public key is written to disk.
	targetPub := addAgentKey(t, keyring, filepath.Join(dir, "id_ed25519.pub"))

	// Add another decoy after.
	addAgentKey(t, keyring, "")

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "id_ed25519.pub",
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   keyring,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")

	parsed, err := sshsig.Unarmor(sig)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(parsed.PublicKey.Marshal(), targetPub.Marshal()),
		"signature must be produced by the target key, not a decoy")
}

// When the .pub path is given with an agent but the agent does not hold the
// matching key, the call returns an error (no private-key fallback for .pub paths).
func TestFromConfigSSHAgentPubKeyNotInAgent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyring := agent.NewKeyring()

	// Write a public key for a key that is NOT in the agent.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "id_ed25519.pub"),
		gossh.MarshalAuthorizedKey(sshPub),
		0o600,
	))

	// Add an unrelated key to the agent.
	addAgentKey(t, keyring, "")

	_, err = auto.FromConfig(auto.Config{
		SigningKey: "id_ed25519.pub",
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   keyring,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, auto.ErrNoPrivateKey)
	assert.Contains(t, err.Error(), "no keys found matching signingKey")
}

// When SigningKey is a non-.pub path and an agent is configured, the
// implementation reads the private key from disk directly (the agent is not
// consulted for non-.pub paths).
func TestFromConfigSSHAgentPrivateKeyPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyring := agent.NewKeyring()

	// Generate the key pair, write the private key to disk, and also add
	// the raw private key to the agent to prove the agent is not used when
	// a non-.pub path is given.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	block, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "id_ed25519"), pem.EncodeToMemory(block), 0o600))

	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), gossh.MarshalAuthorizedKey(sshPub), 0o600))

	require.NoError(t, keyring.Add(agent.AddedKey{ //nolint:exhaustruct // only PrivateKey is required
		PrivateKey: priv,
	}))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "id_ed25519",
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   keyring,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
}

// A non-.pub SigningKey with an agent, where the private key is absent from
// disk, results in a "reading SSH private key" error — there is no implicit
// fallback to the agent.
func TestFromConfigSSHAgentNoPrivateKeyFallback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyring := agent.NewKeyring()

	// Add a key to the agent but do NOT write the private key to disk.
	addAgentKey(t, keyring, filepath.Join(dir, "id_ed25519.pub"))

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "id_ed25519", // private key file does not exist
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   keyring,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading SSH private key")
}

// With no SigningKey and an agent, the first key from the agent is used.
func TestFromConfigSSHAgentFirstKey(t *testing.T) {
	t.Parallel()

	keyring := agent.NewKeyring()
	addAgentKey(t, keyring, "")
	addAgentKey(t, keyring, "")

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "",
		Format:     auto.FormatSSH,
		FS:         nil,
		SSHAgent:   keyring,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
}

// With no SigningKey and an empty agent, ErrNoPrivateKeyInAgent is returned.
func TestFromConfigSSHAgentEmptyAgent(t *testing.T) {
	t.Parallel()

	keyring := agent.NewKeyring()

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "",
		Format:     auto.FormatSSH,
		FS:         nil,
		SSHAgent:   keyring,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, auto.ErrNoPrivateKeyInAgent)
}

// With no SigningKey and no agent, a descriptive error is returned.
func TestFromConfigSSHNoKeyNoAgent(t *testing.T) {
	t.Parallel()

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "",
		Format:     auto.FormatSSH,
		FS:         nil,
		SSHAgent:   nil,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, auto.ErrNoPrivateKey)
}

func TestFromConfigGPG(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeGPGKeyRing(t, filepath.Join(dir, "key.asc"), newGPGEntity(t))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "key.asc",
		Format:     auto.FormatOpenPGP,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN PGP SIGNATURE-----")
	assert.Contains(t, string(sig), "-----END PGP SIGNATURE-----")
}

// Empty format string defaults to FormatOpenPGP.
func TestFromConfigGPGDefaultFormat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeGPGKeyRing(t, filepath.Join(dir, "key.asc"), newGPGEntity(t))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "key.asc",
		Format:     "",
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN PGP SIGNATURE-----")
}

// An empty SigningKey for GPG returns ErrNoPrivateKey immediately, without
// attempting any file read.
func TestFromConfigGPGEmptyKeyPath(t *testing.T) {
	t.Parallel()

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "",
		Format:     auto.FormatOpenPGP,
		FS:         nil,
		SSHAgent:   nil,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, auto.ErrNoPrivateKey)
}

// A key ring whose only entity has an encrypted private key returns
// ErrEncryptedKeyUnsupported.
func TestFromConfigGPGEncryptedKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeEncryptedGPGKey(t, filepath.Join(dir, "key.asc"))

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "key.asc",
		Format:     auto.FormatOpenPGP,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, auto.ErrEncryptedKeyUnsupported)
}

// When the key ring contains multiple entities and the first has an encrypted
// private key, the implementation skips it and uses the first unencrypted one.
func TestFromConfigGPGEncryptedThenUnencrypted(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	encrypted := newGPGEntity(t)
	require.NoError(t, encrypted.PrivateKey.Encrypt([]byte("test-passphrase")))

	unencrypted := newGPGEntity(t)

	var buf bytes.Buffer

	armorWriter, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	require.NoError(t, err)
	// Encrypt clears the in-memory signer, so re-signing is impossible;
	// use the no-resign variant for the encrypted entity.
	require.NoError(t, encrypted.SerializePrivateWithoutSigning(armorWriter, nil))
	require.NoError(t, unencrypted.SerializePrivate(armorWriter, nil))
	require.NoError(t, armorWriter.Close())
	require.NoError(t, os.WriteFile(filepath.Join(dir, "key.asc"), buf.Bytes(), 0o600))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "key.asc",
		Format:     auto.FormatOpenPGP,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN PGP SIGNATURE-----")
}

// A key ring with multiple unencrypted entities uses the first one.
func TestFromConfigGPGMultipleKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeGPGKeyRing(t, filepath.Join(dir, "key.asc"), newGPGEntity(t), newGPGEntity(t))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "key.asc",
		Format:     auto.FormatOpenPGP,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN PGP SIGNATURE-----")
}

// A key ring that contains only public-key material (no private key) returns
// ErrNoPrivateKey.
func TestFromConfigGPGNoPrivateKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeGPGPublicKeyOnly(t, filepath.Join(dir, "key.asc"), newGPGEntity(t))

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "key.asc",
		Format:     auto.FormatOpenPGP,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, auto.ErrNoPrivateKey)
}

// FromConfig expands a leading ~/ to the user's home directory before opening
// key files. The tests override $HOME so the real home directory is never
// touched and a temp dir is used as the fake home.

func TestFromConfigSSHHomeTilde(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	mfs := memfs.New()

	// Generate an SSH key and write the private key into the memfs at the
	// absolute path that expandHome("~/.ssh/id_ed25519") will produce.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_ = pub

	block, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)

	writeFileFS(t, mfs, filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(block))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "~/.ssh/id_ed25519",
		Format:     auto.FormatSSH,
		FS:         mfs,
		SSHAgent:   nil,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
}

func TestFromConfigSSHAgentHomeTildePubKey(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	mfs := memfs.New()

	// Generate a key, add the private half to the agent, and write the
	// public key into the memfs where expandHome will resolve the path.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{ //nolint:exhaustruct // only PrivateKey is required
		PrivateKey: priv,
	}))

	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)

	writeFileFS(t, mfs, filepath.Join(home, ".ssh", "id_ed25519.pub"), gossh.MarshalAuthorizedKey(sshPub))

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "~/.ssh/id_ed25519.pub",
		Format:     auto.FormatSSH,
		FS:         mfs,
		SSHAgent:   keyring,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN SSH SIGNATURE-----")
}

func TestFromConfigGPGHomeTilde(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	mfs := memfs.New()

	// Serialize a GPG key ring and write it into the memfs at the absolute
	// path that expandHome("~/.gnupg/key.asc") will produce.
	entity := newGPGEntity(t)

	var buf bytes.Buffer

	armorWriter, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	require.NoError(t, err)
	require.NoError(t, entity.SerializePrivate(armorWriter, nil))
	require.NoError(t, armorWriter.Close())

	writeFileFS(t, mfs, filepath.Join(home, ".gnupg", "key.asc"), buf.Bytes())

	signer, err := auto.FromConfig(auto.Config{
		SigningKey: "~/.gnupg/key.asc",
		Format:     auto.FormatOpenPGP,
		FS:         mfs,
		SSHAgent:   nil,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(t.Context(), strings.NewReader("hello\n"))
	require.NoError(t, err)
	assert.Contains(t, string(sig), "-----BEGIN PGP SIGNATURE-----")
}

// A ~username/ prefix is not expanded; the path is passed through as-is
// (which will fail to open, confirming no silent misinterpretation occurs).
func TestFromConfigHomeTildeUsernameNotExpanded(t *testing.T) {
	t.Parallel()

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "~otheruser/.ssh/id_ed25519",
		Format:     auto.FormatSSH,
		FS:         nil,
		SSHAgent:   nil,
	})
	require.Error(t, err)
	// The path was not silently mapped to the current user's home; an I/O
	// error is expected because ~otheruser/ is not expanded.
	assert.Contains(t, err.Error(), "reading SSH private key")
}

func TestFromConfigUnknownFormat(t *testing.T) {
	t.Parallel()

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "some/key",
		Format:     "x509",
		FS:         nil,
		SSHAgent:   nil,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, auto.ErrUnsupportedFormat)
}

func TestFromConfigMissingKeyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := auto.FromConfig(auto.Config{
		SigningKey: "nonexistent",
		Format:     auto.FormatSSH,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.Error(t, err)

	_, err = auto.FromConfig(auto.Config{
		SigningKey: "nonexistent",
		Format:     auto.FormatOpenPGP,
		FS:         osfs.New(dir),
		SSHAgent:   nil,
	})
	require.Error(t, err)
}

// writeSSHKey generates an ed25519 private key, writes it as a PEM file to
// path, and returns the corresponding ssh.PublicKey.
//
//nolint:ireturn // gossh.NewPublicKey returns gossh.PublicKey (interface); no concrete type is accessible.
func writeSSHKey(t *testing.T, path string) gossh.PublicKey {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	block, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0o600))

	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)

	return sshPub
}

// addAgentKey generates an ed25519 key, adds the private key to keyring, and
// writes the public key in authorized_keys format to pubPath. It returns the
// ssh.PublicKey so callers can build key:: literals or compare signers.
//
//nolint:ireturn // gossh.NewPublicKey returns gossh.PublicKey (interface); no concrete type is accessible.
func addAgentKey(t *testing.T, keyring agent.Agent, pubPath string) gossh.PublicKey {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, keyring.Add(agent.AddedKey{ //nolint:exhaustruct // only PrivateKey is required
		PrivateKey: priv,
	}))

	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)

	if pubPath != "" {
		require.NoError(t, os.WriteFile(pubPath, gossh.MarshalAuthorizedKey(sshPub), 0o600))
	}

	return sshPub
}

// newGPGEntity creates a fresh OpenPGP entity with an unencrypted private key.
func newGPGEntity(t *testing.T) *openpgp.Entity {
	t.Helper()

	entity, err := openpgp.NewEntity("Test User", "", "test@example.com", nil)
	require.NoError(t, err)

	return entity
}

// writeGPGKeyRing serializes one or more OpenPGP entities (private key
// material included) into a single armored key-ring file at path.
func writeGPGKeyRing(t *testing.T, path string, entities ...*openpgp.Entity) {
	t.Helper()

	var buf bytes.Buffer

	armorWriter, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	require.NoError(t, err)

	for _, entity := range entities {
		require.NoError(t, entity.SerializePrivate(armorWriter, nil))
	}

	require.NoError(t, armorWriter.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

// writeEncryptedGPGKey creates an OpenPGP entity, encrypts its primary
// private key with a passphrase, and writes the armored result to path. The
// resulting file's entity will have PrivateKey.Encrypted == true when parsed.
//
// SerializePrivateWithoutSigning is used because Encrypt clears the in-memory
// crypto.Signer (setting PrivateKey.PrivateKey = nil), which makes the normal
// SerializePrivate fail when it tries to re-sign identity self-certifications.
func writeEncryptedGPGKey(t *testing.T, path string) {
	t.Helper()

	entity := newGPGEntity(t)
	require.NoError(t, entity.PrivateKey.Encrypt([]byte("test-passphrase")))

	var buf bytes.Buffer

	armorWriter, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	require.NoError(t, err)

	require.NoError(t, entity.SerializePrivateWithoutSigning(armorWriter, nil))
	require.NoError(t, armorWriter.Close())

	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

// writeGPGPublicKeyOnly serializes only the public-key material of entity to
// path. When parsed back the resulting entity has PrivateKey == nil.
func writeGPGPublicKeyOnly(t *testing.T, path string, entity *openpgp.Entity) {
	t.Helper()

	var buf bytes.Buffer

	armorWriter, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	require.NoError(t, err)

	require.NoError(t, entity.Serialize(armorWriter))
	require.NoError(t, armorWriter.Close())

	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

// writeFileFS creates a file in a billy filesystem, creating parent
// directories as needed.
func writeFileFS(t *testing.T, fsys billy.Filesystem, path string, data []byte) {
	t.Helper()
	require.NoError(t, fsys.MkdirAll(filepath.Dir(path), 0o700))
	f, err := fsys.Create(path)
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}
