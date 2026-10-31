package remotehelper_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/client"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/plumbing/protocol"
	"github.com/go-git/go-git/v6/plumbing/transport"
	"github.com/go-git/go-git/v6/storage/memory"

	"github.com/go-git/x/transport/remotehelper"
)

// testContext bounds each test, so a helper that stops responding fails the
// test instead of hanging it.
func testContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)

	return ctx
}

func newTestTransport(t *testing.T, gitDir string) *remotehelper.Transport {
	t.Helper()

	helper, err := remotehelper.NewTransport(helperName, remotehelper.Options{Program: os.Args[0], GitDir: gitDir})
	require.NoError(t, err)

	return helper
}

// helperURL builds the URL transport.ParseURL returns for test::<address>.
func helperURL(address string) *url.URL {
	return &url.URL{Scheme: helperName, Opaque: ":" + address} //nolint:exhaustruct // as transport.ParseURL builds it
}

// cloneURL is a test:// URL, which needs no remote helper syntax support
// from the URL parser.
func cloneURL(path string) string {
	return "test://example/?" + url.Values{"path": {path}}.Encode()
}

func request(target *url.URL, command string, version protocol.Version) *transport.Request {
	return &transport.Request{URL: target, Command: command, Args: nil, Protocol: version}
}

// uploadPack is a protocol v0 upload-pack request for test::<address>.
func uploadPack(address string) *transport.Request {
	return request(helperURL(address), transport.UploadPackService, protocol.V0)
}

func newRepository(t *testing.T) (string, plumbing.Hash) {
	t.Helper()

	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dir, "README"), []byte("hello\n"), 0o600)
	require.NoError(t, err)

	worktree, err := repo.Worktree()
	require.NoError(t, err)

	_, err = worktree.Add("README")
	require.NoError(t, err)

	hash, err := worktree.Commit("initial", &git.CommitOptions{ //nolint:exhaustruct // only the author is needed
		Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Unix(0, 0)},
	})
	require.NoError(t, err)

	return dir, hash
}

func TestNewTransportRejectsInvalidNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "a/b", "../x", "a\\b", "-x", ".x", "+x", "a b", "a:b", "a\x00b"} {
		_, err := remotehelper.NewTransport(name, remotehelper.Options{Program: os.Args[0], GitDir: ""})
		require.ErrorIs(t, err, remotehelper.ErrInvalidName, "name %q", name)
	}
}

func TestNewTransportRejectsExt(t *testing.T) {
	t.Parallel()

	_, err := remotehelper.NewTransport("ext", remotehelper.Options{Program: os.Args[0], GitDir: ""})
	require.ErrorIs(t, err, remotehelper.ErrUnsafeHelper)
}

func TestNewTransportProgramNotFound(t *testing.T) {
	t.Parallel()

	_, err := remotehelper.NewTransport(helperName, remotehelper.Options{
		Program: filepath.Join(t.TempDir(), "git-remote-missing"),
		GitDir:  "",
	})
	require.ErrorIs(t, err, remotehelper.ErrProgramNotFound)
}

func TestNewTransportResolvesProgramOnceFromPath(t *testing.T) {
	dir := t.TempDir()

	name := "git-remote-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}

	self, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(dir, name), self, 0o700) //nolint:gosec // the copy must be executable
	require.NoError(t, err)

	t.Setenv("PATH", dir)

	helper, err := remotehelper.NewTransport(helperName, remotehelper.Options{Program: "", GitDir: ""})
	require.NoError(t, err)

	t.Setenv("PATH", "")

	repo, _ := newRepository(t)
	sess, err := helper.Handshake(testContext(t), uploadPack("serve:"+repo))
	require.NoError(t, err)
	require.NoError(t, sess.Close())
}

func TestHandshakeAdvertisesReferences(t *testing.T) {
	t.Parallel()

	repo, head := newRepository(t)
	helper := newTestTransport(t, "")

	for _, mode := range []string{"serve", "serve-crlf"} {
		for _, version := range []protocol.Version{protocol.V0, protocol.V1, protocol.V2} {
			t.Run(mode+"/"+version.String(), func(t *testing.T) {
				t.Parallel()

				ctx := testContext(t)

				sess, err := helper.Handshake(ctx, request(helperURL(mode+":"+repo), transport.UploadPackService, version))
				require.NoError(t, err)

				refs, err := sess.GetRemoteRefs(ctx, nil)
				require.NoError(t, err)

				var got plumbing.Hash

				for _, ref := range refs.References {
					if ref.Name() == plumbing.Master {
						got = ref.Hash()
					}
				}

				assert.Equal(t, head, got)
				require.NoError(t, sess.Close())
			})
		}
	}
}

func TestCloneAndPush(t *testing.T) {
	t.Parallel()

	src, head := newRepository(t)
	helper := newTestTransport(t, "")
	opts := []client.Option{client.WithTransport(helperName, helper)}

	//nolint:exhaustruct // only the URL and client options matter
	cloned, err := git.CloneContext(testContext(t), memory.NewStorage(), nil, &git.CloneOptions{
		URL:           cloneURL(src),
		ClientOptions: opts,
	})
	require.NoError(t, err)

	ref, err := cloned.Reference(plumbing.NewRemoteReferenceName("origin", "master"), true)
	require.NoError(t, err)
	assert.Equal(t, head, ref.Hash())

	dst := t.TempDir()
	_, err = git.PlainInit(dst, true)
	require.NoError(t, err)

	//nolint:exhaustruct // only the URL, refspec and client options matter
	err = cloned.PushContext(testContext(t), &git.PushOptions{
		RemoteURL:     cloneURL(dst),
		RefSpecs:      []config.RefSpec{"refs/remotes/origin/master:refs/heads/main"},
		ClientOptions: opts,
	})
	require.NoError(t, err)

	pushed, err := git.PlainOpen(dst)
	require.NoError(t, err)

	ref, err = pushed.Reference(plumbing.NewBranchReferenceName("main"), true)
	require.NoError(t, err)
	assert.Equal(t, head, ref.Hash())
}

func TestConnectFailures(t *testing.T) {
	t.Parallel()

	helper := newTestTransport(t, "")

	tests := []struct {
		wantErr error
		mode    string
		wantMsg string
	}{
		{wantErr: remotehelper.ErrConnectUnsupported, mode: "caps-only", wantMsg: ""},
		{wantErr: remotehelper.ErrConnectUnsupported, mode: "fallback", wantMsg: "fell back"},
		{wantErr: remotehelper.ErrProtocol, mode: "bad-response", wantMsg: `"nope"`},
		{wantErr: remotehelper.ErrProtocol, mode: "mandatory", wantMsg: `"frobnicate"`},
		{wantErr: remotehelper.ErrProtocol, mode: "abort", wantMsg: "fatal: boom"},
		{wantErr: remotehelper.ErrProtocol, mode: "long-line", wantMsg: "line too long"},
		{wantErr: remotehelper.ErrProtocol, mode: "stderr-flood", wantMsg: ""},
	}

	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			t.Parallel()

			conn, err := helper.Connect(testContext(t), uploadPack(test.mode+":"))
			require.Nil(t, conn)
			require.ErrorIs(t, err, test.wantErr)
			assert.Contains(t, err.Error(), test.wantMsg)
			assert.Less(t, len(err.Error()), 65<<10, "stderr must be bounded")
		})
	}
}

func TestConnectRejectsRequests(t *testing.T) {
	t.Parallel()

	helper := newTestTransport(t, "")

	tests := []struct {
		req  *transport.Request
		name string
	}{
		{req: nil, name: "nil request"},
		{req: request(nil, transport.UploadPackService, protocol.V0), name: "nil URL"},
		{req: request(helperURL("serve:x"), "git-lfs-authenticate", protocol.V0), name: "non-service command"},
		{
			req: &transport.Request{
				URL: helperURL("serve:x"), Command: transport.UploadPackService, Args: []string{"x"}, Protocol: protocol.V0,
			},
			name: "arguments",
		},
		{
			req:  uploadPack("--upload-pack=touch /tmp/pwned"),
			name: "address that looks like an option",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := helper.Connect(testContext(t), test.req)
			require.ErrorIs(t, err, remotehelper.ErrInvalidRequest)
		})
	}
}

func readDump(t *testing.T, path string) helperDump {
	t.Helper()

	b, err := os.ReadFile(path) //nolint:gosec // the path is a test's temp file
	require.NoError(t, err)

	var dump helperDump
	require.NoError(t, json.Unmarshal(b, &dump))

	return dump
}

func TestConnectEnvironment(t *testing.T) {
	t.Setenv("GIT_INDEX_FILE", "/elsewhere/index")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.sshcommand'='evil'")
	t.Setenv("git_work_tree", "/elsewhere")
	t.Setenv("GIT_PROTOCOL", "version=1")
	t.Setenv("REMOTEHELPER_TEST_KEPT", "kept")

	gitDir := t.TempDir()
	helper := newTestTransport(t, gitDir)
	out := filepath.Join(t.TempDir(), "dump.json")
	target := helperURL("dump:" + out)

	_, err := helper.Connect(testContext(t), request(target, transport.UploadPackService, protocol.V2))
	require.ErrorIs(t, err, remotehelper.ErrProtocol)

	dump := readDump(t, out)
	assert.Equal(t, []string{"test::dump:" + out, "dump:" + out}, dump.Args)
	assert.Equal(t, map[string]string{
		"GIT_DIR":                gitDir,
		"GIT_PROTOCOL":           "version=2",
		"REMOTEHELPER_TEST_KEPT": "kept",
	}, dump.Env)
}

func TestConnectArgumentsForSchemeURL(t *testing.T) {
	t.Parallel()

	helper := newTestTransport(t, "")
	out := filepath.Join(t.TempDir(), "dump.json")
	target, err := url.Parse("test://host/repo?" + url.Values{"mode": {"dump"}, "path": {out}}.Encode())
	require.NoError(t, err)

	_, err = helper.Connect(testContext(t), request(target, transport.UploadPackService, protocol.V0))
	require.ErrorIs(t, err, remotehelper.ErrProtocol)

	dump := readDump(t, out)
	assert.Equal(t, []string{target.String(), target.String()}, dump.Args)
	assert.NotContains(t, dump.Env, "GIT_DIR")
	assert.NotContains(t, dump.Env, "GIT_PROTOCOL")
}

func TestConnectContextCancelKillsHelper(t *testing.T) {
	t.Parallel()

	helper := newTestTransport(t, "")

	ctx, cancel := context.WithTimeout(testContext(t), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := helper.Connect(ctx, uploadPack("hang:"))

	require.ErrorIs(t, err, remotehelper.ErrProtocol)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestConnectContextCancelWithStdoutHeldByChild(t *testing.T) {
	t.Parallel()

	helper := newTestTransport(t, "")
	pidFile := filepath.Join(t.TempDir(), "pid")

	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()

	errc := make(chan error, 1)

	go func() {
		_, err := helper.Connect(ctx, uploadPack("orphan:"+pidFile))
		errc <- err
	}()

	var pid int

	require.Eventually(t, func() bool {
		b, err := os.ReadFile(pidFile) //nolint:gosec // the path is a test's temp file
		if err != nil || len(b) == 0 {
			return false
		}

		pid, err = strconv.Atoi(string(b))

		return err == nil
	}, 10*time.Second, 10*time.Millisecond)

	t.Cleanup(func() {
		child, err := os.FindProcess(pid)
		if err == nil {
			_ = child.Kill()
			_, _ = child.Wait()
		}
	})

	cancel()

	select {
	case err := <-errc:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		t.Fatal("Connect did not return after its context was canceled")
	}
}

func TestCloseKillsHelperThatDoesNotExit(t *testing.T) {
	t.Parallel()

	helper := newTestTransport(t, "")

	conn, err := helper.Connect(testContext(t), uploadPack("ignore-eof:"))
	require.NoError(t, err)

	start := time.Now()
	err = conn.Close()

	require.Error(t, err)
	assert.Less(t, time.Since(start), 15*time.Second)
	assert.Equal(t, err, conn.Close(), "Close must be idempotent")
}

func TestStderrIsReportedOnFailedHandshake(t *testing.T) {
	t.Parallel()

	helper := newTestTransport(t, "")
	missing := filepath.Join(t.TempDir(), "missing")

	_, err := helper.Handshake(testContext(t), uploadPack("serve:"+missing))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository not found")
}
