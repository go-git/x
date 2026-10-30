package remotehelper_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v6/plumbing/transport"
	"github.com/go-git/go-git/v6/x/plugin"
	xconfig "github.com/go-git/go-git/v6/x/plugin/config"
)

const (
	// helperEnv makes the test binary act as the remote helper
	// git-remote-test. TestMain sets it after checking it, so only child
	// processes see it.
	helperEnv = "REMOTEHELPER_TEST_RUN_AS_HELPER"

	// helperName is the name the test helper is registered under.
	helperName = "test"

	defaultCapabilities = "option\nconnect\n\n"
)

var errUnsupportedService = errors.New("unsupported service")

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(runHelper(os.Args[1:]))
	}

	err := os.Setenv(helperEnv, "1")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Keep the user's global and system Git configuration, such as
	// commit.gpgSign, out of the repositories the tests create.
	err = plugin.Register(plugin.ConfigLoader(), func() plugin.ConfigSource { return xconfig.NewEmpty() })
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// helperDump is what the "dump" mode records about its invocation.
type helperDump struct {
	Env  map[string]string `json:"env"`
	Args []string          `json:"args"`
}

// fakeHelper is the remote helper side of a test. Its behaviour is selected
// by its address, either "<mode>:<arg>" or a test:// URL with mode and path
// query parameters. The mode of a test:// URL defaults to "serve".
type fakeHelper struct {
	stdin *bufio.Reader
	arg   string
	args  []string
}

func runHelper(args []string) int {
	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: git-remote-test <remote> <address>, got %q\n", args)

		return 2
	}

	mode, arg, _ := strings.Cut(args[1], ":")

	target, err := url.Parse(args[1])
	if err == nil && target.Scheme == helperName {
		mode, arg = target.Query().Get("mode"), target.Query().Get("path")
		if mode == "" {
			mode = "serve"
		}
	}

	run, ok := helperModes()[mode]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", mode)

		return 2
	}

	return run(&fakeHelper{stdin: bufio.NewReader(os.Stdin), arg: arg, args: args})
}

func helperModes() map[string]func(*fakeHelper) int {
	return map[string]func(*fakeHelper) int{
		"abort": func(*fakeHelper) int {
			fmt.Fprintln(os.Stderr, "fatal: boom")

			return 1
		},
		"dump": (*fakeHelper).dump,
		"long-line": func(*fakeHelper) int {
			write(strings.Repeat("a", 1<<20))

			return 0
		},
		"stderr-flood": func(*fakeHelper) int {
			_, _ = os.Stderr.WriteString(strings.Repeat("e", 1<<20))

			return 1
		},
		"hang": func(h *fakeHelper) int {
			h.readLine()
			time.Sleep(time.Hour)

			return 0
		},
		"caps-only": func(h *fakeHelper) int {
			return h.advertiseAndDrain("fetch\n*push\n\n")
		},
		"mandatory": func(h *fakeHelper) int {
			return h.advertiseAndDrain("*frobnicate\nconnect\n\n")
		},
		"fallback": func(h *fakeHelper) int {
			return h.respondToConnect("fallback\n")
		},
		"bad-response": func(h *fakeHelper) int {
			return h.respondToConnect("nope\n")
		},
		"orphan": (*fakeHelper).orphan,
		"sleep": func(*fakeHelper) int {
			time.Sleep(time.Hour)

			return 0
		},
		"ignore-eof": func(h *fakeHelper) int {
			h.respondToConnect("\n")
			time.Sleep(time.Hour)

			return 0
		},
		"serve": func(h *fakeHelper) int {
			return h.serve(defaultCapabilities)
		},
		"serve-crlf": func(h *fakeHelper) int {
			return h.serve("*refspec refs/heads/*:refs/test/*\r\nconnect\r\n\r\n")
		},
	}
}

func write(s string) {
	_, _ = os.Stdout.WriteString(s)
}

func (h *fakeHelper) readLine() string {
	line, _ := h.stdin.ReadString('\n')

	return strings.TrimSuffix(line, "\n")
}

func (h *fakeHelper) advertise(capabilities string) bool {
	if h.readLine() != "capabilities" {
		return false
	}

	write(capabilities)

	return true
}

func (h *fakeHelper) advertiseAndDrain(capabilities string) int {
	if !h.advertise(capabilities) {
		return 2
	}

	_, _ = io.Copy(io.Discard, h.stdin)

	return 0
}

func (h *fakeHelper) respondToConnect(response string) int {
	if !h.advertise(defaultCapabilities) {
		return 2
	}

	h.readLine()
	write(response)

	_, _ = io.Copy(io.Discard, h.stdin)

	return 0
}

func (h *fakeHelper) serve(capabilities string) int {
	if !h.advertise(capabilities) {
		return 2
	}

	service, ok := strings.CutPrefix(h.readLine(), "connect ")
	if !ok {
		return 2
	}

	write("\n")

	err := serveService(service, h.arg, io.NopCloser(h.stdin), os.Stdout)
	// Like git-upload-pack, treat a client hanging up after the
	// advertisement as a normal end of the session.
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, err)

		return 1
	}

	return 0
}

func serveService(service, path string, reader io.ReadCloser, writer io.WriteCloser) error {
	storer, err := transport.DefaultLoader.Load(&url.URL{Path: path}) //nolint:exhaustruct // a loader reads only the path
	if err != nil {
		return fmt.Errorf("loading %q: %w", path, err)
	}

	ctx := context.Background()
	gitProtocol := os.Getenv("GIT_PROTOCOL")

	switch service {
	case transport.UploadPackService:
		req := &transport.UploadPackRequest{
			GitProtocol:          gitProtocol,
			AdvertiseRefs:        false,
			StatelessRPC:         false,
			SkipDeltaCompression: true,
		}

		return transport.UploadPack(ctx, storer, reader, writer, req) //nolint:wrapcheck // test server
	case transport.ReceivePackService:
		req := &transport.ReceivePackRequest{
			GitProtocol:   gitProtocol,
			AdvertiseRefs: false,
			StatelessRPC:  false,
			Hooks:         transport.ReceivePackHooks{PreReceive: nil, PostReceive: nil},
		}

		return transport.ReceivePack(ctx, storer, reader, writer, req) //nolint:wrapcheck // test server
	default:
		return fmt.Errorf("%w: %q", errUnsupportedService, service)
	}
}

// orphan starts a child that keeps the helper's stdout open, records the
// child's PID in the file named by its address, and then hangs.
func (h *fakeHelper) orphan() int {
	child := exec.Command(os.Args[0], "child", "sleep:") //nolint:gosec,noctx // the test binary itself
	child.Stdout = os.Stdout

	err := child.Start()
	if err != nil {
		return 2
	}

	err = os.WriteFile(h.arg, []byte(strconv.Itoa(child.Process.Pid)), 0o600)
	if err != nil {
		return 2
	}

	h.readLine()
	time.Sleep(time.Hour)

	return 0
}

// dump records the helper's arguments and the environment variables the
// tests check into the file named by its address, then fails.
func (h *fakeHelper) dump() int {
	record := helperDump{Env: map[string]string{}, Args: h.args}

	names := []string{
		"GIT_DIR", "GIT_PROTOCOL", "GIT_INDEX_FILE", "GIT_CONFIG_PARAMETERS", "git_work_tree",
		"REMOTEHELPER_TEST_KEPT",
	}
	for _, name := range names {
		if v, ok := os.LookupEnv(name); ok {
			record.Env[name] = v
		}
	}

	b, err := json.Marshal(record)
	if err != nil {
		return 2
	}

	err = os.WriteFile(h.arg, b, 0o600)
	if err != nil {
		return 2
	}

	return 1
}
