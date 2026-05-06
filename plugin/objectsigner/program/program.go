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
// The program must be a bare binary name resolvable on $PATH (e.g. "gpg",
// not "/usr/bin/gpg" or "./gpg").
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
	// ErrInvalidProgram is returned when program is not a bare binary name
	// (i.e. contains a path separator).
	ErrInvalidProgram = errors.New("program must be a bare binary name")
	// ErrProgramNotFound is returned when program cannot be resolved on $PATH.
	ErrProgramNotFound = errors.New("program not found in PATH")
	// ErrEmptySigningKey is returned when no signing key was provided.
	ErrEmptySigningKey = errors.New("signing key is empty")
	// ErrNilMessage is returned when a nil message is passed to Sign.
	ErrNilMessage = errors.New("message is nil")
)

// New returns a signer that invokes program to produce a signature in the
// given format using the provided signing key.
//
// program must be a bare binary name (no path separators) and must resolve
// on $PATH at the time of this call; otherwise [ErrInvalidProgram] or
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

	err := validateProgram(program, lookPath)
	if err != nil {
		return nil, err
	}

	if signingKey == "" {
		return nil, ErrEmptySigningKey
	}

	return &signer{
		commandContext: commandContext,
		format:         format,
		program:        program,
		signingKey:     signingKey,
	}, nil
}

// validateProgram returns nil iff program is a non-empty bare binary name
// resolvable on $PATH.
func validateProgram(program string, lookPath func(string) (string, error)) error {
	if program == "" {
		return ErrEmptyProgram
	}

	if filepath.Base(program) != program {
		return fmt.Errorf("%w: %q", ErrInvalidProgram, program)
	}

	_, err := lookPath(program)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrProgramNotFound, program, err)
	}

	return nil
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

	var stdout, stderr bytes.Buffer

	cmd.SetStdin(message)
	cmd.SetStdout(&stdout)
	cmd.SetStderr(&stderr)

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", s.program, err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// maxSSHSignatureSize bounds how many bytes are read from <bufferFile>.sig
// after ssh-keygen exits. An ssh-keygen sshsig is well under a kilobyte even
// for RSA-4096 keys; 1 MiB leaves ample headroom while preventing a
// pathological signature file from being slurped into memory.
const maxSSHSignatureSize = 1 << 20

// bufferFileMode is the unix file mode used for the temporary buffer file
// holding the message to be signed; the file lives in a 0700 temp dir.
const bufferFileMode = 0o600

// signSSH writes the message to a temporary buffer file, runs
// `<program> -Y sign -n git -f <signingKey> <bufferFile>`, and returns the
// signature read from `<bufferFile>.sig`. Literal public keys are written to a
// temporary key file and signed with `<program> -Y sign -n git -f <keyFile> -U
// <bufferFile>`. Mirrors git's ssh-keygen(1) -Y sign invocation.
//
//nolint:funlen // logically a single procedure; splitting hurts readability.
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

	var signingKeyFile string

	literalKey, isLiteralKey := literalSSHKey(s.signingKey)
	if isLiteralKey {
		signingKeyFile = filepath.Join(dir, "signing-key")

		err = os.WriteFile(signingKeyFile, []byte(literalKey), bufferFileMode)
		if err != nil {
			return nil, fmt.Errorf("writing SSH signing key file: %w", err)
		}
	} else {
		signingKeyFile, err = interpolateSSHSigningKeyPath(s.signingKey)
		if err != nil {
			return nil, err
		}
	}

	args := []string{
		"-Y", "sign",
		"-n", "git",
		"-f", signingKeyFile,
	}
	if isLiteralKey {
		args = append(args, "-U")
	}

	args = append(args, bufferFile)

	cmd := s.commandContext(ctx, s.program, args...)

	var stdout, stderr bytes.Buffer

	cmd.SetStdout(&stdout)
	cmd.SetStderr(&stderr)

	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", s.program, err, stderr.String())
	}

	sigFile, err := os.Open(bufferFile + ".sig") //nolint:gosec // path lives in our own temp dir
	if err != nil {
		return nil, fmt.Errorf("opening SSH signature: %w", err)
	}

	defer func() { _ = sigFile.Close() }()

	sig, err := io.ReadAll(io.LimitReader(sigFile, maxSSHSignatureSize))
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
func literalSSHKey(signingKey string) (string, bool) {
	const literalPrefix = "key::"

	if key, ok := strings.CutPrefix(signingKey, literalPrefix); ok {
		return key, true
	}

	if strings.HasPrefix(signingKey, "ssh-") {
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
