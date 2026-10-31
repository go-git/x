// Package remotehelper runs Git remote helper programs (git-remote-<name>)
// as go-git transports.
//
// Only the "connect" capability of gitremote-helpers(7) is supported. The
// helper is asked to connect to git-upload-pack, git-receive-pack or
// git-upload-archive, after which its standard input and output carry the
// Git pack protocol and go-git drives the exchange just as it does over SSH.
// Helpers that offer only fetch, push, import or export are rejected with
// [ErrConnectUnsupported].
//
// Remote helpers are opt-in, per helper and per client. A [Transport] is only
// used for URLs whose scheme it is registered for:
//
//	tr, err := remotehelper.NewTransport("foo", remotehelper.Options{})
//	if err != nil {
//		return err
//	}
//
//	_, err = git.PlainClone(dir, &git.CloneOptions{
//		URL:           "foo::https://example.com/repo.git",
//		ClientOptions: []client.Option{client.WithTransport("foo", tr)},
//	})
//
// The helper is invoked as Git invokes it for a URL given on the command
// line. For foo::<address> the arguments are the full URL and <address>.
// For foo://<rest> both arguments are the full URL. GIT_DIR is set from
// [Options.GitDir]. The configured remote name that Git would pass as the
// first argument is not known to a transport.
//
// # Security
//
// A remote helper is an arbitrary program that receives part of the URL as an
// argument. URLs are not always chosen by the user: submodule URLs come from
// the repository being cloned. Register only helpers that treat their address
// as data. The "ext" helper runs its address as a command line. Git refuses it
// unless explicitly configured, and [NewTransport] always refuses it.
//
// The program is resolved to an absolute path once, in [NewTransport], so a
// later change to $PATH or the working directory cannot redirect it. Like
// [exec.LookPath], resolution refuses a program found relative to the
// current directory through $PATH.
//
// The helper inherits the environment of the current process, minus the
// variables Git treats as local to a repository (GIT_DIR, GIT_WORK_TREE,
// GIT_INDEX_FILE, GIT_CONFIG_PARAMETERS and similar). Those describe the
// process's own repository, not the one go-git operates on.
//
// Credentials embedded in a URL are passed as arguments, which other local
// users may be able to see in the process list. Git behaves the same way.
package remotehelper

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v6/plumbing/protocol"
	"github.com/go-git/go-git/v6/plumbing/transport"
)

// Sentinel errors.
var (
	// ErrInvalidName is returned for a helper name that Git would not
	// accept as a URL scheme.
	ErrInvalidName = errors.New("invalid remote helper name")
	// ErrUnsafeHelper is returned for helpers that execute their address.
	ErrUnsafeHelper = errors.New("unsafe remote helper")
	// ErrProgramNotFound is returned when the helper program cannot be
	// resolved to an executable.
	ErrProgramNotFound = errors.New("remote helper program not found")
	// ErrInvalidRequest is returned for a request a helper cannot serve,
	// such as a command other than a Git service, extra arguments, or an
	// address that would be read as an option.
	ErrInvalidRequest = errors.New("invalid remote helper request")
	// ErrConnectUnsupported is returned when the helper does not offer the
	// connect capability or falls back from connecting to a service.
	ErrConnectUnsupported = errors.New("remote helper does not support connect")
	// ErrProtocol is returned when the helper violates the remote helper
	// protocol or exits before the connection is established.
	ErrProtocol = errors.New("remote helper protocol error")
)

const (
	// maxStderrSize bounds how much of the helper's stderr is kept for
	// error messages. Anything beyond it is discarded.
	maxStderrSize = 64 << 10 // 64 KiB

	// waitDelay is how long Close waits for the helper to exit once its
	// stdin and stdout are closed, before killing it. It also bounds how
	// long Wait waits for a stderr held open by a descendant process.
	waitDelay = 5 * time.Second
)

// Options configures a [Transport].
type Options struct {
	// Program is the helper executable, either a path or a bare name
	// looked up in $PATH. It defaults to "git-remote-<name>".
	Program string

	// GitDir is exported to the helper as GIT_DIR, as Git does for the
	// repository it runs in. A relative path is made absolute. When
	// empty, GIT_DIR is not set.
	GitDir string
}

// Transport runs a remote helper for each connection. It implements
// [transport.Transport] and [transport.Connector], and is safe for
// concurrent use.
type Transport struct {
	name    string
	program string
	gitDir  string
}

var (
	_ transport.Transport = (*Transport)(nil)
	_ transport.Connector = (*Transport)(nil)
)

// NewTransport returns a transport that runs the remote helper called name.
//
// The program is resolved to an absolute path now. It fails with
// [ErrProgramNotFound] when it cannot be resolved, so a missing helper is
// reported at configuration time rather than on first use.
func NewTransport(name string, opts Options) (*Transport, error) {
	if !validName(name) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidName, name)
	}

	if name == "ext" {
		return nil, fmt.Errorf("%w: %q runs its address as a command", ErrUnsafeHelper, name)
	}

	program := opts.Program
	if program == "" {
		program = "git-remote-" + name
	}

	resolved, err := exec.LookPath(program)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrProgramNotFound, program, err)
	}

	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("resolving absolute path for %q: %w", program, err)
	}

	gitDir := opts.GitDir
	if gitDir != "" {
		gitDir, err = filepath.Abs(gitDir)
		if err != nil {
			return nil, fmt.Errorf("resolving absolute path for %q: %w", opts.GitDir, err)
		}
	}

	return &Transport{
		name:    name,
		program: resolved,
		gitDir:  gitDir,
	}, nil
}

// Handshake connects to the service named by req.Command and reads the
// server's advertisement.
//
//nolint:ireturn // transport.Transport requires returning the Session interface.
func (t *Transport) Handshake(ctx context.Context, req *transport.Request) (transport.Session, error) {
	helper, err := t.connect(ctx, req)
	if err != nil {
		return nil, err
	}

	sess, err := transport.NewStreamSession(helper, req.Command)
	if err != nil {
		// NewStreamSession closes the connection, so the helper has
		// exited and its stderr is complete.
		return nil, helper.withStderr(err)
	}

	return sess, nil
}

// Connect starts the helper and asks it to connect to the service named by
// req.Command. The returned connection carries the service's raw protocol.
//
// When ctx is done the helper is killed and the connection is closed, so
// ctx must outlive the connection.
//
//nolint:ireturn // transport.Connector requires returning the Conn interface.
func (t *Transport) Connect(ctx context.Context, req *transport.Request) (transport.Conn, error) {
	return t.connect(ctx, req)
}

func (t *Transport) connect(ctx context.Context, req *transport.Request) (*conn, error) {
	err := validateRequest(req)
	if err != nil {
		return nil, err
	}

	helper, err := t.start(ctx, req)
	if err != nil {
		return nil, err
	}

	err = helper.handshake(req.Command)
	if err != nil {
		helper.abort()

		// A done context kills the helper, which then looks like an
		// aborted session. Report the cause as well.
		ctxErr := ctx.Err()
		if ctxErr != nil {
			err = fmt.Errorf("%w: %w", err, ctxErr)
		}

		return nil, helper.withStderr(err)
	}

	return helper, nil
}

// start runs the helper with Git's arguments for req.URL. See get_helper in
// https://github.com/git/git/blob/v2.56.0/transport-helper.c#L129-L157.
func (t *Transport) start(ctx context.Context, req *transport.Request) (*conn, error) {
	url := req.URL.String()

	// The program was resolved by NewTransport and the arguments are
	// passed without a shell, as Git passes them.
	cmd := exec.CommandContext(ctx, t.program, url, removeExtForce(url)) //nolint:gosec // see above
	cmd.Env = t.environ(req.Protocol)
	cmd.WaitDelay = waitDelay

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()

		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr := &boundedBuffer{buf: nil, limit: maxStderrSize, mu: sync.Mutex{}}
	cmd.Stderr = stderr

	err = cmd.Start()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()

		return nil, fmt.Errorf("starting remote helper %q: %w", t.name, err)
	}

	helper := &conn{
		cmd:       cmd,
		r:         bufio.NewReader(stdout),
		stderr:    stderr,
		stdin:     stdin,
		stdout:    stdout,
		closeErr:  nil,
		stop:      nil,
		name:      t.name,
		closeOnce: sync.Once{},
	}

	// Killing the helper does not end a read from stdout while a process
	// it started still holds the pipe open. Closing the pipes does.
	helper.stop = context.AfterFunc(ctx, helper.closePipes)

	return helper, nil
}

// environ returns the inherited environment without the variables Git
// treats as local to a repository, plus GIT_DIR and GIT_PROTOCOL.
func (t *Transport) environ(version protocol.Version) []string {
	// os.Environ returns a copy, so it can be filtered in place.
	env := slices.DeleteFunc(os.Environ(), isLocalRepoEnv)

	if t.gitDir != "" {
		env = append(env, "GIT_DIR="+t.gitDir)
	}

	if v := transport.GitProtocolEnv(version); v != "" {
		env = append(env, "GIT_PROTOCOL="+v)
	}

	return env
}

// validName reports whether name is non-empty and made of the characters
// Git accepts in a URL scheme, which also keeps path separators out of the
// program name.
func validName(name string) bool {
	if name == "" {
		return false
	}

	for i := range len(name) {
		if !isURLSchemeChar(i == 0, name[i]) {
			return false
		}
	}

	return true
}

// isURLSchemeChar mirrors Git's is_urlschemechar. See
// https://github.com/git/git/blob/v2.56.0/url.c#L5-L19.
func isURLSchemeChar(first bool, c byte) bool {
	alphanumeric := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
	special := c == '+' || c == '-' || c == '.'

	return alphanumeric || (!first && special)
}

// validateRequest rejects requests the connect command cannot express, and
// addresses a helper could mistake for an option.
func validateRequest(req *transport.Request) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("%w: nil request or URL", ErrInvalidRequest)
	}

	switch req.Command {
	case transport.UploadPackService, transport.ReceivePackService, transport.UploadArchiveService:
	default:
		return fmt.Errorf("%w: unsupported service %q", ErrInvalidRequest, req.Command)
	}

	if len(req.Args) > 0 {
		return fmt.Errorf("%w: connect takes no arguments", ErrInvalidRequest)
	}

	address := removeExtForce(req.URL.String())
	if strings.HasPrefix(address, "-") {
		return fmt.Errorf("%w: address %q would be read as an option", ErrInvalidRequest, address)
	}

	return nil
}

// removeExtForce mirrors Git's remove_ext_force: for <transport>::<address>
// it returns <address>, and any other URL unchanged. See
// https://github.com/git/git/blob/v2.56.0/transport-helper.c#L107-L115.
func removeExtForce(url string) string {
	_, after, found := strings.Cut(url, ":")
	if found && strings.HasPrefix(after, ":") {
		return after[1:]
	}

	return url
}

// isLocalRepoEnv reports whether kv sets one of the variables Git removes
// before running a command against another repository, or GIT_PROTOCOL,
// which is set from the request instead. See local_repo_env in
// https://github.com/git/git/blob/v2.56.0/environment.c#L84-L101.
//
// Names are matched case-insensitively because Windows treats environment
// variable names that way.
func isLocalRepoEnv(kv string) bool {
	name, _, _ := strings.Cut(kv, "=")

	switch strings.ToUpper(name) {
	case "GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"GIT_CONFIG",
		"GIT_CONFIG_PARAMETERS",
		"GIT_CONFIG_COUNT",
		"GIT_OBJECT_DIRECTORY",
		"GIT_DIR",
		"GIT_WORK_TREE",
		"GIT_IMPLICIT_WORK_TREE",
		"GIT_GRAFT_FILE",
		"GIT_INDEX_FILE",
		"GIT_NO_REPLACE_OBJECTS",
		"GIT_REPLACE_REF_BASE",
		"GIT_PREFIX",
		"GIT_SHALLOW_FILE",
		"GIT_COMMON_DIR",
		"GIT_PROTOCOL":
		return true
	default:
		return false
	}
}

// conn is a connected remote helper. After a successful handshake its stdin
// and stdout carry the requested service's protocol.
type conn struct {
	cmd *exec.Cmd
	// r buffers stdout from the first capability line onwards, so bytes
	// the helper sent right after the connect response are not lost.
	r         *bufio.Reader
	stderr    *boundedBuffer
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	closeErr  error
	stop      func() bool
	name      string
	closeOnce sync.Once
}

var _ transport.Conn = (*conn)(nil)

func (c *conn) Reader() io.Reader      { return c.r }
func (c *conn) Writer() io.WriteCloser { return c.stdin }

// Stderr returns what the helper has written to stderr so far.
// StreamSession reports it in place of a failed operation's error.
func (c *conn) Stderr() io.Reader {
	b := c.stderr.Bytes()
	if len(b) == 0 {
		return nil
	}

	return bytes.NewReader(b)
}

// Close closes the helper's stdin and stdout and waits for it to exit,
// killing it if it has not exited after waitDelay. It returns an error if
// the helper exited unsuccessfully.
func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		c.stop()
		// Nothing reads stdout from here on, so close it too. A helper
		// blocked writing to it then fails instead of hanging.
		c.closePipes()

		c.closeErr = c.wait()
	})

	return c.closeErr
}

// handshake runs the capabilities and connect commands. See get_helper and
// run_connect in
// https://github.com/git/git/blob/v2.56.0/transport-helper.c.
func (c *conn) handshake(service string) error {
	canConnect, err := c.capabilities()
	if err != nil {
		return err
	}

	if !canConnect {
		return ErrConnectUnsupported
	}

	return c.connectService(service)
}

// capabilities asks for the helper's capabilities and reports whether it
// can connect.
func (c *conn) capabilities() (bool, error) {
	err := c.send("capabilities\n")
	if err != nil {
		return false, err
	}

	canConnect := false

	for {
		line, err := c.readLine()
		if err != nil {
			return false, err
		}

		if line == "" {
			return canConnect, nil
		}

		capability, mandatory := strings.CutPrefix(line, "*")
		if capability == "connect" {
			canConnect = true
		} else if mandatory && !knownCapability(capability) {
			return false, fmt.Errorf("%w: unknown mandatory capability %q", ErrProtocol, capability)
		}
	}
}

// connectService asks the helper to connect to service. On success the
// next byte on stdout is the first byte of the service's output.
func (c *conn) connectService(service string) error {
	err := c.send("connect " + service + "\n")
	if err != nil {
		return err
	}

	line, err := c.readLine()
	if err != nil {
		return err
	}

	switch line {
	case "":
		return nil
	case "fallback":
		return fmt.Errorf("%w: helper fell back for %s", ErrConnectUnsupported, service)
	default:
		return fmt.Errorf("%w: unknown response to connect: %q", ErrProtocol, line)
	}
}

func (c *conn) send(line string) error {
	_, err := io.WriteString(c.stdin, line)
	if err != nil {
		return fmt.Errorf("%w: writing to helper: %w", ErrProtocol, err)
	}

	return nil
}

// readLine reads one LF or CRLF terminated line, as strbuf_getline does. A
// line longer than the read buffer is a protocol error, which bounds the
// memory a misbehaving helper can make the handshake use.
func (c *conn) readLine() (string, error) {
	line, err := c.r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", fmt.Errorf("%w: line too long", ErrProtocol)
		}

		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("%w: helper %q aborted session", ErrProtocol, c.name)
		}

		return "", fmt.Errorf("%w: reading from helper: %w", ErrProtocol, err)
	}

	line = bytes.TrimSuffix(line[:len(line)-1], []byte{'\r'})

	return string(line), nil
}

func (c *conn) wait() error {
	done := make(chan error, 1)

	go func() { done <- c.cmd.Wait() }()

	timer := time.NewTimer(waitDelay)
	defer timer.Stop()

	var err error
	select {
	case err = <-done:
	case <-timer.C:
		_ = c.cmd.Process.Kill()
		err = <-done
	}

	if err != nil {
		return c.withStderr(fmt.Errorf("remote helper %q: %w", c.name, err))
	}

	return nil
}

// abort kills the helper and reaps it. It is used when the connection fails
// before it is handed to the caller.
func (c *conn) abort() {
	c.closeOnce.Do(func() {
		c.stop()
		_ = c.cmd.Process.Kill()
		c.closePipes()
		_ = c.cmd.Wait()
	})
}

// closePipes closes the helper's stdin and stdout, which ends any read or
// write on them in progress.
func (c *conn) closePipes() {
	_ = c.stdin.Close()
	_ = c.stdout.Close()
}

// withStderr appends the helper's stderr to err.
func (c *conn) withStderr(err error) error {
	msg := strings.TrimSpace(string(c.stderr.Bytes()))
	if msg == "" {
		return err
	}

	return fmt.Errorf("%w: %s", err, msg)
}

// knownCapability reports whether Git understands capability, in which case
// a helper may mark it mandatory. Only connect is used here, but Git also
// ignores the others when it connects. See get_helper in
// https://github.com/git/git/blob/v2.56.0/transport-helper.c#L182-L234.
func knownCapability(capability string) bool {
	switch capability {
	case "fetch", "option", "push", "import", "bidi-import", "export",
		"check-connectivity", "connect", "stateless-connect", "signed-tags":
		return true
	}

	for _, prefix := range []string{"refspec ", "export-marks ", "import-marks ", "no-private-update", "object-format"} {
		if strings.HasPrefix(capability, prefix) {
			return true
		}
	}

	return false
}

// boundedBuffer keeps the first limit bytes written to it and discards the
// rest. It never fails a write, so the helper is not killed by SIGPIPE for
// writing too much to stderr. It is safe for concurrent use because os/exec
// copies stderr from its own goroutine.
type boundedBuffer struct {
	buf   []byte
	limit int
	mu    sync.Mutex
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if room := b.limit - len(b.buf); room > 0 {
		b.buf = append(b.buf, data[:min(room, len(data))]...)
	}

	return len(data), nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	return bytes.Clone(b.buf)
}
