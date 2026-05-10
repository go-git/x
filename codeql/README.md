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
- Resources in functions that return Repository or Storer types
- **Any function that contains a defer statement with a Close() call** (conservative heuristic)

**Known limitations:**
- Very conservative: if a function has ANY `defer ... Close()` statement, all resources in that function are assumed to be cleaned up
- Will not detect leaks in functions that create multiple resources but only close some of them
- Does not track inter-procedural dataflow (resources passed to other functions)
- Designed to minimize false positives at the cost of potentially missing some true leaks

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
