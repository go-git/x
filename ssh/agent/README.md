# agent

SSH agent client for SSH clients, including
[go-git](https://github.com/go-git/go-git).

`New` connects to the running agent:

- Unix-like systems: the socket named by `SSH_AUTH_SOCK`.
- Windows: [Pageant](https://www.chiark.greenend.org.uk/~sgtatham/putty/) when
  it is running, otherwise the Windows OpenSSH agent pipe
  (`\\.\pipe\openssh-ssh-agent`).

The returned `*Agent` embeds `golang.org/x/crypto/ssh/agent.ExtendedAgent`,
so the full agent protocol is available (`Signers`, `List`, `Sign`, `Add`,
...). It owns the connection to the agent: call `Close` once you are done.

go-git v6 uses the agent by default through an internal client that supports
`SSH_AUTH_SOCK` and the Windows OpenSSH agent pipe, but not Pageant. Use this
module for Pageant, or to control the agent connection yourself.

## Usage with go-git

```go
import (
	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/client"
	"github.com/go-git/go-git/v6/plumbing/transport/ssh"
	"github.com/go-git/x/ssh/agent"
)

a, err := agent.New()
if err != nil {
	return err
}
defer func() { _ = a.Close() }()

auth := &ssh.PublicKeysCallback{
	User:     "git",
	Callback: a.Signers,
}

r, err := git.PlainClone("/tmp/repo", &git.CloneOptions{
	URL:           "git@github.com:go-git/go-git.git",
	ClientOptions: []client.Option{client.WithSSHAuth(auth)},
})
if err != nil {
	return err
}
defer func() { _ = r.Close() }()
```

With `golang.org/x/crypto/ssh` directly, use `a.AuthMethod()` in
`ssh.ClientConfig.Auth`.

## Upstream

The agent discovery is a copy of [github.com/xanzy/ssh-agent](https://github.com/xanzy/ssh-agent)
at [v0.3.3](https://github.com/xanzy/ssh-agent/tree/v0.3.3)
(commit `0fa644ba07f41bbe341c7f3d59bd30443ff13002`), which go-git vendored
before v6. Differences from upstream:

- `New` returns an `*Agent` that owns the connection and closes it in
  `Close`, instead of an `agent.Agent` and a `net.Conn` (which upstream
  returned as nil on Windows, leaking the named pipe).
- Errors for a missing agent wrap `ErrAgentNotFound`.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE), kept
from upstream. `agent_windows.go` and `pageant_windows.go` derive from
[github.com/davidmz/go-pageant](https://github.com/davidmz/go-pageant) and are
licensed under the MIT License, as stated in their file headers.
