# CodeQL Queries for go-git

This directory contains CodeQL queries for detecting common issues in go-git usage.

## Queries

### Unclosed Resources (`unclosed-resources.ql`)

Detects instances where `Repository` or `Storage` objects are created but never closed, which can lead to file handle leaks, particularly on Windows.

**What it detects:**
- Calls to `PlainOpen`, `Init`, `Clone`, and other repository creation functions
- Calls to `NewStorage` and `NewStorageWithOptions`
- Submodule and worktree operations that return repositories
- Missing `Close()` calls or `defer` cleanup patterns

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
```

## Running the queries

### Using CodeQL CLI

```bash
codeql database create /tmp/go-git-db --language=go --source-root=/path/to/go-git
codeql query run codeql/queries/unclosed-resources.ql --database=/tmp/go-git-db
```

### Using GitHub Actions

The queries run automatically via the CodeQL workflow on pull requests.

## Contributing

To add a new query:

1. Create a `.ql` file in `codeql/queries/`
2. Include proper metadata (name, description, severity, tags)
3. Test the query against go-git codebase
4. Document the query in this README
