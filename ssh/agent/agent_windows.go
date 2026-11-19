//
// Copyright (c) 2014 David Mzareulyan
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software
// and associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute,
// sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial
// portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
// BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

// Originally from: https://github.com/xanzy/ssh-agent/blob/v0.3.3/sshagent_windows.go
// Upstream commit: 0fa644ba07f41bbe341c7f3d59bd30443ff13002
// MIT LICENSE: https://github.com/davidmz/go-pageant/blob/master/LICENSE.txt

//go:build windows

package agent

import (
	"fmt"
	"io"
	"sync"

	"github.com/Microsoft/go-winio"
)

const sshAgentPipe = `\\.\pipe\openssh-ssh-agent`

// Available reports whether Pageant or the Windows OpenSSH agent is running.
func Available() bool {
	if pageantWindow() != 0 {
		return true
	}

	conn, err := winio.DialPipe(sshAgentPipe, nil)
	if err != nil {
		return false
	}

	_ = conn.Close()

	return true
}

// New connects to Pageant when it is running, and to the Windows OpenSSH
// agent named pipe otherwise. It returns an error wrapping ErrAgentNotFound
// when neither is available. The caller must Close the returned Agent.
func New() (*Agent, error) {
	if pageantWindow() != 0 {
		return newAgent(new(pageantConn), nil), nil
	}

	return dialPipe(sshAgentPipe)
}

func dialPipe(name string) (*Agent, error) {
	conn, err := winio.DialPipe(name, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: Pageant is not running and %s cannot be opened: %w",
			ErrAgentNotFound, name, err)
	}

	return newAgent(conn, conn), nil
}

// pageantConn adapts Pageant's request and response messages to the
// io.ReadWriter used by the agent client.
type pageantConn struct {
	buf []byte
	mu  sync.Mutex
}

func (c *pageantConn) Write(msg []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, err := query(msg)
	if err != nil {
		return 0, err
	}

	c.buf = append(c.buf, resp...)

	return len(msg), nil
}

func (c *pageantConn) Read(buf []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.buf) == 0 {
		return 0, io.EOF
	}

	n := copy(buf, c.buf)
	c.buf = c.buf[n:]

	return n, nil
}
