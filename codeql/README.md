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
- Resources assigned to struct fields (managed by struct lifecycle)
- Direct calls to `memory.NewStorage` (no cleanup needed)
- Factory functions that only create memory storage
- Resources passed to wrapper types that are properly closed
- Resources cleaned up via returned callback functions
- Resources closed via type assertions: `if c, ok := st.(io.Closer); ok { c.Close() }`

**Detection techniques:**
- Precise variable name tracking for defer statements
- Tuple assignment support: `r, err := git.Clone(...)`
- Type assertion pattern recognition
- Wrapper pattern detection (e.g., transactional storage wrapping filesystem storage)
- Returned callback function analysis
- Testing cleanup via `t.Cleanup()` or `b.Cleanup()`

**Known limitations:**
- Does not track inter-procedural dataflow beyond one level (e.g., resources passed to helper functions)
- Complex ownership transfer patterns may require manual verification
- Designed for high precision (minimal false positives) while maintaining full leak detection coverage

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

The queries run automatically via the CodeQL workflow on pull requests and include test files.

## Contributing

To add a new query:

1. Create a `.ql` file in `codeql/queries/`
2. Include proper metadata (name, description, severity, tags)
3. Test the query against go-git codebase
4. Document the query in this README
