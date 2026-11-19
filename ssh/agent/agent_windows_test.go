//go:build windows

//nolint:testpackage // tests dial test pipes through the unexported dialPipe helper.
package agent

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/Microsoft/go-winio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPipeName(t *testing.T) string {
	t.Helper()

	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(t, err)

	return `\\.\pipe\go-git-x-ssh-agent-test-` + hex.EncodeToString(b)
}

func newTestAgent(t *testing.T) (*Agent, *fakeAgent) {
	t.Helper()

	name := testPipeName(t)
	listener, err := winio.ListenPipe(name, nil)
	require.NoError(t, err)

	fake := serveFakeAgent(t, listener)

	client, err := dialPipe(name)
	require.NoError(t, err)

	return client, fake
}

func TestDialPipeNotFound(t *testing.T) {
	t.Parallel()

	client, err := dialPipe(testPipeName(t))
	require.ErrorIs(t, err, ErrAgentNotFound)
	assert.Nil(t, client)
}
