// Package agent connects to a running SSH agent and exposes its keys for SSH
// client authentication.
//
// On Unix-like systems the agent is reached through the socket named by the
// SSH_AUTH_SOCK environment variable. On Windows, Pageant is used when it is
// running, and the Windows OpenSSH agent named pipe otherwise.
//
// With go-git, pass Agent.Signers as the Callback of a PublicKeysCallback from
// github.com/go-git/go-git/v6/plumbing/transport/ssh, and close the Agent
// once the SSH operations are done.
package agent

import (
	"errors"
	"io"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

// ErrAgentNotFound is returned by New when no SSH agent can be found.
var ErrAgentNotFound = errors.New("ssh agent: no agent found")

// Agent is a client of a running SSH agent. It owns the connection to the
// agent, which stays open until Close is called. Every method of the embedded
// ExtendedAgent, such as Signers, fails once the Agent is closed.
type Agent struct {
	xagent.ExtendedAgent

	conn      io.Closer
	closeErr  error
	closeOnce sync.Once
}

func newAgent(rw io.ReadWriter, conn io.Closer) *Agent {
	agt := new(Agent)
	agt.ExtendedAgent = xagent.NewClient(rw)
	agt.conn = conn

	return agt
}

// AuthMethod returns an ssh.AuthMethod that authenticates with the keys held
// by the agent.
//
//nolint:ireturn // ssh.AuthMethod is the interface ssh.ClientConfig takes.
func (a *Agent) AuthMethod() gossh.AuthMethod {
	return gossh.PublicKeysCallback(a.Signers)
}

// Close closes the connection to the agent. It is safe to call more than
// once, and only the first call closes the connection. Close is a no-op for
// Pageant, which has no connection to close.
func (a *Agent) Close() error {
	if a == nil || a.conn == nil {
		return nil
	}

	a.closeOnce.Do(func() {
		a.closeErr = a.conn.Close()
	})

	return a.closeErr
}
