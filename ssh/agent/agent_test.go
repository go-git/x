//nolint:testpackage // tests dial test sockets through the unexported dial helpers.
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

type fakeAgent struct {
	key      gossh.PublicKey
	conns    []net.Conn
	connsMu  sync.Mutex
	accepted atomic.Int32
	open     atomic.Int32
}

func (f *fakeAgent) track(conn net.Conn) {
	f.connsMu.Lock()
	defer f.connsMu.Unlock()

	f.conns = append(f.conns, conn)
	f.accepted.Add(1)
	f.open.Add(1)
}

func (f *fakeAgent) closeConns() {
	f.connsMu.Lock()
	defer f.connsMu.Unlock()

	for _, conn := range f.conns {
		_ = conn.Close()
	}
}

// serveFakeAgent serves an in-memory keyring holding one ed25519 key on
// listener until the test ends.
func serveFakeAgent(t *testing.T, listener net.Listener) *fakeAgent {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	var key xagent.AddedKey

	key.PrivateKey = priv

	keyring := xagent.NewKeyring()
	require.NoError(t, keyring.Add(key))

	signers, err := keyring.Signers()
	require.NoError(t, err)

	fake := new(fakeAgent)
	fake.key = signers[0].PublicKey()

	var group sync.WaitGroup

	group.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			fake.track(conn)

			group.Go(func() {
				_ = xagent.ServeAgent(keyring, conn)
				_ = conn.Close()

				fake.open.Add(-1)
			})
		}
	})

	t.Cleanup(func() {
		_ = listener.Close()

		fake.closeConns()
		group.Wait()
	})

	return fake
}

func (f *fakeAgent) requireClosed(t *testing.T) {
	t.Helper()

	require.Eventually(t, func() bool {
		return f.accepted.Load() == 1 && f.open.Load() == 0
	}, 2*time.Second, 10*time.Millisecond,
		"agent connections: accepted %d, open %d, want accepted 1, open 0",
		f.accepted.Load(), f.open.Load())
}

func TestSigners(t *testing.T) {
	t.Parallel()

	client, fake := newTestAgent(t)
	t.Cleanup(func() { _ = client.Close() })

	signers, err := client.Signers()
	require.NoError(t, err)
	require.Len(t, signers, 1)
	assert.Equal(t, fake.key.Marshal(), signers[0].PublicKey().Marshal())
}

func TestClose(t *testing.T) {
	t.Parallel()

	client, fake := newTestAgent(t)
	require.Eventually(t, func() bool { return fake.open.Load() == 1 },
		2*time.Second, 10*time.Millisecond)

	require.NoError(t, client.Close())
	fake.requireClosed(t)
	require.NoError(t, client.Close())

	_, err := client.Signers()
	require.Error(t, err)
}

func TestCloseWithoutConn(t *testing.T) {
	t.Parallel()

	var nilAgent *Agent
	require.NoError(t, nilAgent.Close())
	require.NoError(t, new(Agent).Close())
}

func TestAuthMethod(t *testing.T) {
	t.Parallel()

	client, fake := newTestAgent(t)
	t.Cleanup(func() { _ = client.Close() })

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostKey, err := gossh.NewSignerFromKey(hostPriv)
	require.NoError(t, err)

	var serverCfg gossh.ServerConfig

	serverCfg.PublicKeyCallback = func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		if string(key.Marshal()) != string(fake.key.Marshal()) {
			return nil, assert.AnError
		}

		return new(gossh.Permissions), nil
	}
	serverCfg.AddHostKey(hostKey)

	var listenCfg net.ListenConfig

	listener, err := listenCfg.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	serverErr := make(chan error, 1)

	go func() {
		serverErr <- acceptSSH(listener, &serverCfg)
	}()

	var dialer net.Dialer

	clientConn, err := dialer.DialContext(t.Context(), "tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })

	var clientCfg gossh.ClientConfig

	clientCfg.User = "git"
	clientCfg.Auth = []gossh.AuthMethod{client.AuthMethod()}
	clientCfg.HostKeyCallback = gossh.FixedHostKey(hostKey.PublicKey())

	conn, _, _, err := gossh.NewClientConn(clientConn, "test", &clientCfg)
	require.NoError(t, err)

	_ = conn.Close()

	require.NoError(t, <-serverErr)
}

// acceptSSH accepts one connection on listener and completes the SSH
// handshake on it.
func acceptSSH(listener net.Listener, cfg *gossh.ServerConfig) error {
	netConn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}

	defer func() { _ = netConn.Close() }()

	conn, _, _, err := gossh.NewServerConn(netConn, cfg)
	if err != nil {
		return fmt.Errorf("ssh handshake: %w", err)
	}

	_ = conn.Close()

	return nil
}
