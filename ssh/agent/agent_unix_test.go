//go:build !windows

//nolint:testpackage // tests dial test sockets through the unexported dial helper.
package agent

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listenUnix listens on a Unix socket in a new temporary directory.
func listenUnix(t *testing.T) (net.Listener, string) {
	t.Helper()

	// t.TempDir paths can exceed the Unix socket path limit.
	dir, err := os.MkdirTemp("", "agent") //nolint:usetesting // see above.
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "agent.sock")

	var listenCfg net.ListenConfig

	listener, err := listenCfg.Listen(t.Context(), "unix", sock)
	require.NoError(t, err)

	return listener, sock
}

func newTestAgent(t *testing.T) (*Agent, *fakeAgent) {
	t.Helper()

	listener, sock := listenUnix(t)
	fake := serveFakeAgent(t, listener)

	client, err := dial(sock)
	require.NoError(t, err)

	return client, fake
}

func TestNew(t *testing.T) {
	listener, sock := listenUnix(t)
	fake := serveFakeAgent(t, listener)
	t.Setenv("SSH_AUTH_SOCK", sock)

	assert.True(t, Available())

	client, err := New()
	require.NoError(t, err)

	signers, err := client.Signers()
	require.NoError(t, err)
	require.Len(t, signers, 1)
	assert.Equal(t, fake.key.Marshal(), signers[0].PublicKey().Marshal())

	require.NoError(t, client.Close())
	fake.requireClosed(t)
}

func TestNewWithoutAuthSock(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	assert.False(t, Available())

	client, err := New()
	require.ErrorIs(t, err, ErrAgentNotFound)
	assert.Nil(t, client)
}

func TestNewDialError(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing.sock"))

	client, err := New()
	require.ErrorIs(t, err, syscall.ENOENT)
	require.NotErrorIs(t, err, ErrAgentNotFound)
	assert.Nil(t, client)
}
