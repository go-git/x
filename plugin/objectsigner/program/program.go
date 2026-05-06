// Package program provides an object signer that shells out to an arbitrary
// external binary using Git's invocation conventions for the requested
// signing format. The binary name is supplied by the caller. This package does
// not assume or default to any particular tool.
//
// For OpenPGP and X.509, the message is fed via stdin and the signature is
// read from stdout, matching git's invocation of gpg-style binaries.
//
// For SSH, the message is written to a temporary file, the binary is invoked
// with ssh-keygen(1)'s -Y sign argument layout, and the signature is read
// from the corresponding .sig file. Literal public keys, using Git's key::
// prefix or the deprecated raw ssh-* form, are written to a temporary key
// file and passed with -U so ssh-keygen signs via ssh-agent.
//
// The program may be a bare binary name resolved on $PATH (e.g. "gpg") or
// a path to an executable (e.g. "/usr/bin/gpg" or "./gpg").
package program

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// Format identifies the signing protocol implemented by the external binary.
// Values mirror git's gpg.format configuration.
type Format string

const (
	// FormatOpenPGP selects gpg-style invocation: stdin/stdout with
	// --status-fd=2 -bsau <signingKey>.
	FormatOpenPGP Format = "openpgp"
	// FormatSSH selects ssh-keygen(1) -Y sign invocation.
	FormatSSH Format = "ssh"
	// FormatX509 selects gpgsm-style invocation, identical to FormatOpenPGP.
	FormatX509 Format = "x509"
)

// Sentinel errors.
var (
	// ErrUnsupportedFormat is returned for an unrecognized signing format.
	ErrUnsupportedFormat = errors.New("unsupported signing format")
	// ErrEmptyProgram is returned when no program name was provided.
	ErrEmptyProgram = errors.New("program is empty")
	// ErrProgramNotFound is returned when program cannot be resolved as
	// either a path to an existing executable or a bare name on $PATH.
	ErrProgramNotFound = errors.New("program not found")
	// ErrEmptySigningKey is returned when no signing key was provided.
	ErrEmptySigningKey = errors.New("signing key is empty")
	// ErrNilMessage is returned when a nil message is passed to Sign.
	ErrNilMessage = errors.New("message is nil")
	// ErrOutputLimitExceeded is returned when the external program writes
	// more bytes to stdout or stderr than the configured limit.
	ErrOutputLimitExceeded = errors.New("output limit exceeded")
	// ErrSignatureTooLarge is returned when the signature produced by the
	// external program exceeds the maximum permitted size.
	ErrSignatureTooLarge = errors.New("signature too large")
)

// New returns a signer that invokes program to produce a signature in the
// given format using the provided signing key.
//
// program is either a bare binary name resolved on $PATH or a path to an
// executable; it must resolve at the time of this call, otherwise
// [ErrProgramNotFound] is returned.
//
// For OpenPGP and X.509, signingKey is the key ID or fingerprint passed to
// the binary's -u flag.
//
// For SSH, signingKey is the path to a private (or, when an agent is in use,
// public) key file passed to ssh-keygen's -f flag, or a literal public key
// prefixed with key::. For compatibility with Git, raw ssh-* public keys are
// also accepted as literals. Path-style SSH keys have ~ and ~user prefixes
// expanded before they are passed to ssh-keygen.
//
//nolint:revive // returning unexported *signer is intentional; callers use it via Signer interface inference
func New(format Format, program, signingKey string) (*signer, error) {
	return newSigner(
		format,
		program,
		signingKey,
		exec.LookPath,
		func(ctx context.Context, program string, args ...string) command {
			return newExecCommand(ctx, program, args...)
		},
	)
}

func newSigner(
	format Format,
	program string,
	signingKey string,
	lookPath func(string) (string, error),
	commandContext func(ctx context.Context, program string, args ...string) command,
) (*signer, error) {
	switch format {
	case FormatOpenPGP, FormatSSH, FormatX509:
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
	}

	resolvedProgram, err := resolveProgram(program, lookPath)
	if err != nil {
		return nil, err
	}

	if signingKey == "" {
		return nil, ErrEmptySigningKey
	}

	return &signer{
		commandContext: commandContext,
		format:         format,
		program:        resolvedProgram,
		signingKey:     signingKey,
	}, nil
}

// resolveProgram returns the absolute path that lookPath resolves program
// to. When program contains a path separator, lookPath (exec.LookPath in
// production) verifies the file exists and is executable and returns the
// path unchanged; otherwise it is searched for on $PATH. The resolved path
// is captured at New() time and reused by Sign() so a $PATH change between
// the two calls cannot redirect execution to a different binary.
func resolveProgram(program string, lookPath func(string) (string, error)) (string, error) {
	if program == "" {
		return "", ErrEmptyProgram
	}

	resolved, err := lookPath(program)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %w", ErrProgramNotFound, program, err)
	}

	return resolved, nil
}

// Sign reads message and returns the signature produced by the external
// binary.
func (s *signer) Sign(message io.Reader) ([]byte, error) {
	if message == nil {
		return nil, ErrNilMessage
	}

	switch s.format {
	case FormatOpenPGP, FormatX509:
		return s.signStdio(context.Background(), message)
	case FormatSSH:
		return s.signSSH(context.Background(), message)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, s.format)
	}
}

// signStdio runs `<program> --status-fd=2 -bsau <signingKey>`, piping the
// message to stdin and returning the signature read from stdout. Mirrors
// git's invocation of gpg-style binaries.
func (s *signer) signStdio(ctx context.Context, message io.Reader) ([]byte, error) {
	cmd := s.commandContext(ctx, s.program, "--status-fd=2", "-bsau", s.signingKey)

	stdout := newLimitWriter("stdout", maxSignatureSize)
	stderr := newLimitWriter("stderr", maxStderrSize)

	cmd.SetStdin(message)
	cmd.SetStdout(stdout)
	cmd.SetStderr(stderr)

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", s.program, err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// maxSignatureSize bounds how many bytes are accepted from the external
// program's stdout (gpg/gpgsm) or its SSH signature file (ssh-keygen). Real
// signatures are well under a kilobyte even for RSA-4096 keys; 1 MiB leaves
// ample headroom while preventing a misbehaving program from causing
// unbounded memory growth.
const maxSignatureSize = 1 << 20 // 1 MiB

// maxStderrSize bounds how many bytes are buffered from the external
// program's stderr; the value is included verbatim in error messages, so
// the limit doubles as a cap on error-message size.
const maxStderrSize = 64 << 10 // 64 KiB

// bufferFileMode is the unix file mode used for the temporary buffer file
// holding the message to be signed; the file lives in a 0700 temp dir.
const bufferFileMode = 0o600

// signSSH writes the message to a temporary buffer file, runs
// `<program> -Y sign -n git -f <signingKey> <bufferFile>`, and returns the
// signature read from `<bufferFile>.sig`. Literal public keys are written to a
// temporary key file and signed with `<program> -Y sign -n git -f <keyFile> -U
// <bufferFile>`. Mirrors git's ssh-keygen(1) -Y sign invocation.
func (s *signer) signSSH(ctx context.Context, message io.Reader) ([]byte, error) {
	dir, err := os.MkdirTemp("", "objectsigner-program-")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}

	defer func() { _ = os.RemoveAll(dir) }()

	bufferFile := filepath.Join(dir, "buffer")

	err = writeBufferFile(bufferFile, message)
	if err != nil {
		return nil, err
	}

	signingKeyFile, isLiteralKey, err := s.prepareSSHSigningKey(dir)
	if err != nil {
		return nil, err
	}

	args := []string{"-Y", "sign", "-n", "git", "-f", signingKeyFile}
	if isLiteralKey {
		args = append(args, "-U")
	}

	args = append(args, bufferFile)

	cmd := s.commandContext(ctx, s.program, args...)

	stdout := newLimitWriter("stdout", maxSignatureSize)
	stderr := newLimitWriter("stderr", maxStderrSize)

	cmd.SetStdout(stdout)
	cmd.SetStderr(stderr)

	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", s.program, err, stderr.String())
	}

	return readSSHSignature(bufferFile + ".sig")
}

// prepareSSHSigningKey returns the path to pass to ssh-keygen's -f flag and
// reports whether the user-supplied signing key is a literal public key
// (which requires the -U flag). For literal keys, the key material is
// written to a file in dir; for path keys, ~ and ~user prefixes are
// expanded to match git's behaviour.
func (s *signer) prepareSSHSigningKey(dir string) (string, bool, error) {
	literalKey, isLiteralKey := literalSSHKey(s.signingKey)
	if isLiteralKey {
		path := filepath.Join(dir, "signing-key")

		err := os.WriteFile(path, []byte(literalKey), bufferFileMode)
		if err != nil {
			return "", false, fmt.Errorf("writing SSH signing key file: %w", err)
		}

		return path, true, nil
	}

	path, err := interpolateSSHSigningKeyPath(s.signingKey)
	if err != nil {
		return "", false, err
	}

	return path, false, nil
}

// readSSHSignature returns the signature ssh-keygen wrote to sigPath,
// rejecting files that exceed maxSignatureSize. The size is verified via
// Stat before reading so that a truncated read cannot silently return a
// partial signature.
func readSSHSignature(sigPath string) ([]byte, error) {
	sigInfo, err := os.Stat(sigPath)
	if err != nil {
		return nil, fmt.Errorf("stating SSH signature: %w", err)
	}

	if sigInfo.Size() > maxSignatureSize {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrSignatureTooLarge, sigInfo.Size(), maxSignatureSize)
	}

	sig, err := os.ReadFile(sigPath) //nolint:gosec // path lives in our own temp dir
	if err != nil {
		return nil, fmt.Errorf("reading SSH signature: %w", err)
	}

	return sig, nil
}

func writeBufferFile(path string, message io.Reader) error {
	//nolint:gosec // path lives in our own temp dir
	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		bufferFileMode,
	)
	if err != nil {
		return fmt.Errorf("creating buffer file: %w", err)
	}

	_, copyErr := io.Copy(file, message)
	closeErr := file.Close()

	if copyErr != nil {
		return fmt.Errorf("writing buffer file: %w", copyErr)
	}

	if closeErr != nil {
		return fmt.Errorf("closing buffer file: %w", closeErr)
	}

	return nil
}

// literalSSHKey reports whether signingKey is one of Git's literal SSH public
// key forms and returns the key material to write to ssh-keygen's -f file.
//
// The key:: prefix is unambiguous and matches whatever follows it. The
// deprecated bare ssh-* form additionally requires whitespace, so an entry
// must look like an authorized_keys line ("ssh-<algo> <base64-key>...");
// this avoids treating file paths such as "ssh-key" as literal keys.
func literalSSHKey(signingKey string) (string, bool) {
	const literalPrefix = "key::"

	if key, ok := strings.CutPrefix(signingKey, literalPrefix); ok {
		return key, true
	}

	if strings.HasPrefix(signingKey, "ssh-") && strings.ContainsAny(signingKey, " \t") {
		return signingKey, true
	}

	return "", false
}

// interpolateSSHSigningKeyPath expands SSH key-file paths the same way Git
// does before passing them to ssh-keygen's -f flag.
func interpolateSSHSigningKeyPath(signingKey string) (string, error) {
	if !strings.HasPrefix(signingKey, "~") {
		return signingKey, nil
	}

	if signingKey == "~" || strings.HasPrefix(signingKey, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expanding SSH signing key path: %w", err)
		}

		if signingKey == "~" {
			return filepath.Clean(home), nil
		}

		return filepath.Join(home, signingKey[2:]), nil
	}

	nameAndPath := signingKey[1:]
	username, rest, _ := strings.Cut(nameAndPath, "/")

	usr, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("expanding SSH signing key path %q: %w", signingKey, err)
	}

	if rest == "" {
		return usr.HomeDir, nil
	}

	return filepath.Join(usr.HomeDir, rest), nil
}

// limitWriter accumulates writes into an internal buffer until limit bytes
// are reached, after which Write returns [ErrOutputLimitExceeded]. It is
// used to bound the memory consumed by an external program's stdout and
// stderr.
type limitWriter struct {
	label string
	buf   bytes.Buffer
	limit int
}

func newLimitWriter(label string, limit int) *limitWriter {
	return &limitWriter{
		label: label,
		buf:   bytes.Buffer{},
		limit: limit,
	}
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.limit {
		return 0, fmt.Errorf("%s: %w (limit %d bytes)", w.label, ErrOutputLimitExceeded, w.limit)
	}

	return w.buf.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never returns an error.
}

func (w *limitWriter) Bytes() []byte {
	return w.buf.Bytes()
}

func (w *limitWriter) String() string {
	return w.buf.String()
}

type signer struct {
	commandContext func(ctx context.Context, program string, args ...string) command
	format         Format
	program        string
	signingKey     string
}

type command interface {
	SetStdin(r io.Reader)
	SetStdout(w io.Writer)
	SetStderr(w io.Writer)
	Run() error
}

type execCommand struct {
	cmd *exec.Cmd
}

func newExecCommand(ctx context.Context, program string, args ...string) *execCommand {
	cmd := exec.CommandContext(ctx, program, args...)

	return &execCommand{
		cmd: cmd,
	}
}

func (c *execCommand) SetStdin(stdin io.Reader) {
	c.cmd.Stdin = stdin
}

func (c *execCommand) SetStdout(stdout io.Writer) {
	c.cmd.Stdout = stdout
}

func (c *execCommand) SetStderr(stderr io.Writer) {
	c.cmd.Stderr = stderr
}

func (c *execCommand) Run() error {
	err := c.cmd.Run()
	if err != nil {
		return fmt.Errorf("running command: %w", err)
	}

	return nil
}
