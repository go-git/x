# CodeQL Queries for go-git

This directory contains CodeQL queries for detecting common issues in go-git usage.

## Queries

### Unclosed Resources (`unclosed-resources.ql`)

Detects instances where `Repository` or `Storage` objects are created but never closed, which can lead to file handle leaks, particularly on Windows.

**What it detects:**
- Calls to `PlainOpen`, `Init`, `Clone`, and other repository creation functions
- Calls to `NewStorage` and `NewStorageWithOptions`
- Missing `Close()` calls on created resources

**What it excludes (to avoid false positives):**
- Factory functions that return Repository/Storage to the caller
- Resources stored in struct literals (managed by struct lifecycle)
- Direct calls to `memory.NewStorage` (no cleanup needed)
- Factory functions that only create memory storage
- Factory functions that return existing resources without creating new ones (getters)
- Factory functions that register their own cleanup (cache-or-create patterns)
- Resources passed to wrapper types that are properly closed (including inline arguments)
- Resources cleaned up via returned callback functions
- Resources closed via type assertions: `if c, ok := st.(io.Closer); ok { c.Close() }`
- Error path tests where creation is followed by error assertions (`Error`, `ErrorIs`, `NotNil`, etc.)

**Detection techniques:**
- Precise variable name tracking for defer statements and cleanup callbacks
- Tuple assignment support: `r, err := git.Clone(...)`
- Variable declaration support: `var sto storage.Storer = filesystem.NewStorage(...)`
- Type assertion pattern recognition
- Wrapper pattern detection (e.g., transactional storage wrapping filesystem storage)
- Inline argument detection: `r := Open(NewStorage(...))`
- Struct field cleanup patterns: `s.Field = Create(); r := s.Field; t.Cleanup(func() { r.Close() })`
- Returned callback function analysis
- Testing cleanup via `t.Cleanup()` or `b.Cleanup()` (with dataflow tracking)
- Error path detection to filter out tests that expect creation to fail

**Known limitations:**
- Does not track inter-procedural dataflow beyond one level (e.g., resources passed to helper functions)
- Suite-level cleanup in test lifecycle methods (e.g., `TearDownTest()`) may not be detected
- Complex ownership transfer patterns may require manual verification
- Local dataflow only - does not track through struct fields in general (exception: specific cleanup patterns)
- Designed for high precision (minimal false positives) while maintaining high recall for actual resource leaks

**Example violations:**

```go
// BAD: No Close() call
func bad() error {
    r, err := git.PlainOpen("/path/to/repo")
    if err != nil {
        return err
    }
    // Missing: defer func() { _ = r.Close() }()
    _, err = r.Head()
    return err
}

// GOOD: Proper cleanup
func good() error {
    r, err := git.PlainOpen("/path/to/repo")
    if err != nil {
        return err
    }
    defer func() { _ = r.Close() }()
    _, err = r.Head()
    return err
}

// ALSO GOOD: Factory function (caller's responsibility)
func createRepo() (*git.Repository, error) {
    return git.PlainOpen("/path/to/repo")
}

// ALSO GOOD: Error path test (expects creation to fail)
func TestOpenInvalid(t *testing.T) {
    r, err := git.PlainOpen("/invalid/path")
    require.Error(t, err)  // Test expects error
    require.Nil(t, r)
}

// ALSO GOOD: Testing cleanup callback
func TestWithCleanup(t *testing.T) {
    r, err := git.PlainOpen("/path/to/repo")
    require.NoError(t, err)
    t.Cleanup(func() { _ = r.Close() })
    // ... use r
}

// ALSO GOOD: Inline wrapper pattern
func example() error {
    r, err := git.Open(filesystem.NewStorage(...), fs)  // Storage passed inline
    if err != nil {
        return err
    }
    defer func() { _ = r.Close() }()  // Closing r also closes storage
    return nil
}
```

## Running the queries

### Using CodeQL CLI

To include test files in the analysis (recommended):

```bash
CODEQL_EXTRACTOR_GO_OPTION_EXTRACT_TESTS=true \
  codeql database create /tmp/go-git-db --language=go --source-root=/path/to/go-git
codeql query run codeql/queries/unclosed-resources.ql --database=/tmp/go-git-db
```

Without the environment variable, `*_test.go` files are excluded by default.

### Using GitHub Actions

The queries run automatically via the CodeQL workflow on pushes to main and can be manually triggered via workflow_dispatch. Test files are included in the analysis.

## Contributing

To add a new query:

1. Create a `.ql` file in `codeql/queries/`
2. Include proper metadata (name, description, severity, tags)
3. Test the query against go-git codebase
4. Document the query in this README
