//nolint:testpackage // tests use internal constructor injection without exporting test-only hooks.
package program

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testProgram = "git-signer"

var (
	errLookPathNotFound = errors.New("not found")
	errStdioExit        = errors.New("exit 7")
	errSSHExit          = errors.New("exit 1")
)

func resolvedTestProgram() string {
	abs, err := filepath.Abs(filepath.Join(string(os.PathSeparator), "mock", testProgram))
	if err != nil {
		panic(err)
	}

	return abs
}

//nolint:funlen // table test enumerates each validation branch.
func TestNew(t *testing.T) {
	t.Parallel()

	lookPath := func(binary string) (string, error) {
		if binary == "missing" {
			return "", errLookPathNotFound
		}

		return filepath.Join(string(os.PathSeparator), "mock", binary), nil
	}
	commandContext, _ := stubCommand(nil)

	tests := []struct {
		wantErr    error
		name       string
		format     Format
		program    string
		signingKey string
	}{
		{
			name: "valid openpgp", format: FormatOpenPGP,
			program: testProgram, signingKey: "ABC123", wantErr: nil,
		},
		{
			name: "valid ssh", format: FormatSSH,
			program: testProgram, signingKey: "/path/to/key", wantErr: nil,
		},
		{
			name: "valid x509", format: FormatX509,
			program: testProgram, signingKey: "ABC123", wantErr: nil,
		},
		{
			name: "unknown format", format: "unknown",
			program: testProgram, signingKey: "k", wantErr: ErrUnsupportedFormat,
		},
		{
			name: "empty program", format: FormatOpenPGP,
			program: "", signingKey: "k", wantErr: ErrEmptyProgram,
		},
		{
			name: "absolute path program", format: FormatOpenPGP,
			program:    filepath.Join(string(os.PathSeparator), "usr", "bin", testProgram),
			signingKey: "k", wantErr: nil,
		},
		{
			name: "relative path program", format: FormatOpenPGP,
			program:    "." + string(os.PathSeparator) + testProgram,
			signingKey: "k", wantErr: nil,
		},
		{
			name: "subdir program", format: FormatOpenPGP,
			program:    filepath.Join("bin", testProgram),
			signingKey: "k", wantErr: nil,
		},
		{
			name: "program not found", format: FormatOpenPGP,
			program: "missing", signingKey: "k", wantErr: ErrProgramNotFound,
		},
		{
			name: "empty signing key", format: FormatOpenPGP,
			program: testProgram, signingKey: "", wantErr: ErrEmptySigningKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			signer, err := newSigner(test.format, test.program, test.signingKey, lookPath, commandContext)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				require.Nil(t, signer)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, signer)
		})
	}
}

func TestNew_RelativeResolvedPathBecomesAbsolute(t *testing.T) {
	t.Parallel()

	lookPath := func(string) (string, error) {
		return filepath.Join("relative", "to", "cwd", testProgram), nil
	}
	commandContext, _ := stubCommand(nil)

	signer, err := newSigner(FormatOpenPGP, "./"+testProgram, "k", lookPath, commandContext)
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.True(t, filepath.IsAbs(signer.program),
		"program should be anchored to an absolute path, got %q", signer.program)
}

func TestSign_NilMessage(t *testing.T) {
	t.Parallel()

	signer, _ := newTestSigner(t, FormatOpenPGP, "ABC", nil)

	sig, err := signer.Sign(nil)
	require.ErrorIs(t, err, ErrNilMessage)
	require.Nil(t, sig)
}

func TestSign_StdioFormats(t *testing.T) {
	t.Parallel()

	formats := []Format{FormatOpenPGP, FormatX509}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()

			var stdin string

			signer, calls := newTestSigner(t, format, "KEYID", func(cmd *mockCommand) error {
				data, err := io.ReadAll(cmd.stdin)
				require.NoError(t, err)

				stdin = string(data)

				_, err = io.WriteString(cmd.stdout, "STDIO-SIG\n")
				require.NoError(t, err)

				return nil
			})

			sig, err := signer.Sign(strings.NewReader("commit body\n"))
			require.NoError(t, err)
			assert.Equal(t, "STDIO-SIG\n", string(sig))
			assert.Equal(t, "commit body\n", stdin)

			require.Len(t, calls(), 1)
			assert.Equal(t, resolvedTestProgram(), calls()[0].program)
			assert.Equal(t, []string{"--status-fd=2", "-bsau", "KEYID"}, calls()[0].args)
		})
	}
}

func TestSign_StdioFailure(t *testing.T) {
	t.Parallel()

	signer, _ := newTestSigner(t, FormatOpenPGP, "KEYID", func(cmd *mockCommand) error {
		_, _ = io.WriteString(cmd.stderr, "stdio failed")

		return errStdioExit
	})

	sig, err := signer.Sign(strings.NewReader("body"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stdio failed")
	require.Nil(t, sig)
}

func TestSign_SSH(t *testing.T) {
	t.Parallel()

	var buffer string

	signer, calls := newTestSigner(t, FormatSSH, "/path/to/key", func(cmd *mockCommand) error {
		bufferFile := cmd.args[len(cmd.args)-1]

		data, err := os.ReadFile(bufferFile) //nolint:gosec // path is generated by Sign in a temp dir
		require.NoError(t, err)

		buffer = string(data)

		return writeSignatureFile(bufferFile)
	})

	sig, err := signer.Sign(strings.NewReader("commit body\n"))
	require.NoError(t, err)
	assert.Equal(t, "SSH-SIG\n", string(sig))
	assert.Equal(t, "commit body\n", buffer)

	require.Len(t, calls(), 1)
	args := calls()[0].args
	require.Len(t, args, 7)
	assert.Equal(t, []string{"-Y", "sign", "-n", "git", "-f", "/path/to/key"}, args[:6])
	assert.True(t,
		strings.HasSuffix(args[6], string(os.PathSeparator)+"buffer"),
		"buffer file path: %q", args[6])
}

func TestSign_SSHExpandsHomePath(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("user home unavailable: %v", err)
	}

	signer, calls := newTestSigner(t, FormatSSH, "~/.ssh/id_ed25519", func(cmd *mockCommand) error {
		bufferFile := cmd.args[len(cmd.args)-1]

		return writeSignatureFile(bufferFile)
	})

	sig, err := signer.Sign(strings.NewReader("commit body\n"))
	require.NoError(t, err)
	assert.Equal(t, "SSH-SIG\n", string(sig))

	require.Len(t, calls(), 1)
	args := calls()[0].args
	require.Len(t, args, 7)
	assert.Equal(t, []string{
		"-Y", "sign",
		"-n", "git",
		"-f", filepath.Join(home, ".ssh", "id_ed25519"),
	}, args[:6])
}

func TestSign_SSHLiteralKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		signingKey  string
		wantKeyFile string
	}{
		{
			name:        "key prefix",
			signingKey:  "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest comment",
			wantKeyFile: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest comment",
		},
		{
			name:        "raw ssh key",
			signingKey:  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDtest comment",
			wantKeyFile: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDtest comment",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var buffer, key string

			signer, calls := newTestSigner(t, FormatSSH, test.signingKey, func(cmd *mockCommand) error {
				keyFile := argAfter(cmd.args, "-f")
				keyData, err := os.ReadFile(keyFile) //nolint:gosec // path is generated by Sign in a temp dir
				require.NoError(t, err)

				key = string(keyData)

				bufferFile := cmd.args[len(cmd.args)-1]
				bufferData, err := os.ReadFile(bufferFile) //nolint:gosec // path is generated by Sign in a temp dir
				require.NoError(t, err)

				buffer = string(bufferData)

				return writeSignatureFile(bufferFile)
			})

			sig, err := signer.Sign(strings.NewReader("commit body\n"))
			require.NoError(t, err)
			assert.Equal(t, "SSH-SIG\n", string(sig))
			assert.Equal(t, "commit body\n", buffer)
			assert.Equal(t, test.wantKeyFile, key)

			require.Len(t, calls(), 1)
			args := calls()[0].args
			require.Len(t, args, 8)
			assert.Equal(t, []string{"-Y", "sign", "-n", "git", "-f"}, args[:5])
			assert.True(t,
				strings.HasSuffix(args[5], string(os.PathSeparator)+"signing-key"),
				"key file path: %q", args[5])
			assert.Equal(t, "-U", args[6])
			assert.True(t,
				strings.HasSuffix(args[7], string(os.PathSeparator)+"buffer"),
				"buffer file path: %q", args[7])
		})
	}
}

func TestSign_SSHFailure(t *testing.T) {
	t.Parallel()

	signer, _ := newTestSigner(t, FormatSSH, "/path/to/key", func(cmd *mockCommand) error {
		_, _ = io.WriteString(cmd.stderr, "ssh failed")

		return errSSHExit
	})

	sig, err := signer.Sign(strings.NewReader("body"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh failed")
	require.Nil(t, sig)
}

func TestSign_SSHPathPrefixedSshDash(t *testing.T) {
	t.Parallel()

	signer, calls := newTestSigner(t, FormatSSH, "ssh-key-path", func(cmd *mockCommand) error {
		bufferFile := cmd.args[len(cmd.args)-1]

		return writeSignatureFile(bufferFile)
	})

	sig, err := signer.Sign(strings.NewReader("body"))
	require.NoError(t, err)
	require.NotNil(t, sig)

	require.Len(t, calls(), 1)
	args := calls()[0].args
	require.Len(t, args, 7)
	assert.Equal(t, []string{"-Y", "sign", "-n", "git", "-f", "ssh-key-path"}, args[:6])
}

func TestSign_StdioOutputTooLarge(t *testing.T) {
	t.Parallel()

	signer, _ := newTestSigner(t, FormatOpenPGP, "KEYID", func(cmd *mockCommand) error {
		oversized := make([]byte, maxSignatureSize+1)

		_, err := cmd.stdout.Write(oversized)
		if err != nil {
			return fmt.Errorf("oversized stdout: %w", err)
		}

		return nil
	})

	sig, err := signer.Sign(strings.NewReader("body"))
	require.ErrorIs(t, err, ErrOutputLimitExceeded)
	assert.Contains(t, err.Error(), "stdout")
	require.Nil(t, sig)
}

func TestSign_StderrTooLarge(t *testing.T) {
	t.Parallel()

	signer, _ := newTestSigner(t, FormatOpenPGP, "KEYID", func(cmd *mockCommand) error {
		oversized := make([]byte, maxStderrSize+1)

		_, err := cmd.stderr.Write(oversized)
		if err != nil {
			return fmt.Errorf("oversized stderr: %w", err)
		}

		return nil
	})

	sig, err := signer.Sign(strings.NewReader("body"))
	require.ErrorIs(t, err, ErrOutputLimitExceeded)
	assert.Contains(t, err.Error(), "stderr")
	require.Nil(t, sig)
}

func TestSign_SSHSignatureTooLarge(t *testing.T) {
	t.Parallel()

	signer, _ := newTestSigner(t, FormatSSH, "/path/to/key", func(cmd *mockCommand) error {
		bufferFile := cmd.args[len(cmd.args)-1]

		oversized := make([]byte, maxSignatureSize+1)

		err := os.WriteFile(bufferFile+".sig", oversized, bufferFileMode)
		if err != nil {
			return fmt.Errorf("writing oversized signature: %w", err)
		}

		return nil
	})

	sig, err := signer.Sign(strings.NewReader("body"))
	require.ErrorIs(t, err, ErrSignatureTooLarge)
	require.Nil(t, sig)
}

type mockCommand struct {
	run     func(*mockCommand) error
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	program string
	args    []string
}

func (c *mockCommand) SetStdin(stdin io.Reader) {
	c.stdin = stdin
}

func (c *mockCommand) SetStdout(stdout io.Writer) {
	c.stdout = stdout
}

func (c *mockCommand) SetStderr(stderr io.Writer) {
	c.stderr = stderr
}

func (c *mockCommand) Run() error {
	if c.run == nil {
		return nil
	}

	return c.run(c)
}

func newTestSigner(
	t *testing.T,
	format Format,
	signingKey string,
	run func(*mockCommand) error,
) (*signer, func() []*mockCommand) {
	t.Helper()

	commandContext, calls := stubCommand(run)

	signer, err := newSigner(format, testProgram, signingKey, lookPathSuccess, commandContext)
	require.NoError(t, err)

	return signer, calls
}

func stubCommand(run func(*mockCommand) error) (
	func(_ context.Context, binary string, args ...string) command,
	func() []*mockCommand,
) {
	calls := make([]*mockCommand, 0, 1)

	commandContext := func(_ context.Context, binary string, args ...string) command {
		cmd := &mockCommand{
			run:     run,
			stdin:   nil,
			stdout:  nil,
			stderr:  nil,
			program: binary,
			args:    append([]string(nil), args...),
		}
		calls = append(calls, cmd)

		return cmd
	}

	return commandContext, func() []*mockCommand {
		return calls
	}
}

func lookPathSuccess(binary string) (string, error) {
	return filepath.Join(string(os.PathSeparator), "mock", binary), nil
}

func writeSignatureFile(bufferFile string) error {
	err := os.WriteFile(bufferFile+".sig", []byte("SSH-SIG\n"), bufferFileMode)
	if err != nil {
		return fmt.Errorf("writing SSH signature: %w", err)
	}

	return nil
}

func argAfter(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}

	return ""
}
