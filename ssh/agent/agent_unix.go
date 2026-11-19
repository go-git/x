//
// Copyright 2015, Sander van Harmelen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Originally from: https://github.com/xanzy/ssh-agent/blob/v0.3.3/sshagent.go
// Upstream commit: 0fa644ba07f41bbe341c7f3d59bd30443ff13002

//go:build !windows

package agent

import (
	"context"
	"fmt"
	"net"
	"os"
)

const authSockEnv = "SSH_AUTH_SOCK"

// New connects to the SSH agent listening on the Unix socket named by the
// SSH_AUTH_SOCK environment variable. It returns an error wrapping
// ErrAgentNotFound when SSH_AUTH_SOCK is not set. The caller must Close the
// returned Agent.
func New() (*Agent, error) {
	sock := os.Getenv(authSockEnv)
	if sock == "" {
		return nil, fmt.Errorf("%w: %s is not set", ErrAgentNotFound, authSockEnv)
	}

	return dial(sock)
}

// Available reports whether SSH_AUTH_SOCK is set.
func Available() bool {
	return os.Getenv(authSockEnv) != ""
}

func dial(sock string) (*Agent, error) {
	var dialer net.Dialer

	conn, err := dialer.DialContext(context.Background(), "unix", sock)
	if err != nil {
		return nil, fmt.Errorf("ssh agent: connect to %s: %w", authSockEnv, err)
	}

	return newAgent(conn, conn), nil
}
