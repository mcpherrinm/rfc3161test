# Contributing

## Building and Testing

```bash
go build ./...
go test -race ./...
```

## Linting

CI uses [golangci-lint](https://golangci-lint.run/) via `golangci/golangci-lint-action@v9`, which installs the latest version automatically.

To run the same linter locally, install golangci-lint v2 and run:

```bash
golangci-lint run ./...
```

The linter configuration is in `.golangci.yml`. All linters are enabled by default (`default: all`), with `testpackage` and the deprecated `wsl` disabled (replaced by `wsl_v5`).

### Installing golangci-lint

See https://golangci-lint.run/welcome/install/ or download directly:

```bash
# Example for v2.8.0 on Linux amd64:
curl -sSfL https://github.com/golangci/golangci-lint/releases/download/v2.8.0/golangci-lint-2.8.0-linux-amd64.tar.gz | tar xz
./golangci-lint-2.8.0-linux-amd64/golangci-lint run ./...
```

### Common Lint Rules

- **exhaustruct**: All struct fields must be explicitly initialized, or the line must have a `//nolint:exhaustruct` directive with a reason.
- **wrapcheck**: Errors returned from external packages must be wrapped with `fmt.Errorf("context: %w", err)`.
- **err113**: Do not use `errors.New()` inline in return statements; define package-level sentinel errors instead.
- **lll**: Lines must not exceed 120 characters.
- **varnamelen**: Variable names must be long enough for their scope.
- **mnd**: Magic numbers need a `//nolint:mnd` directive with a reason.

## Fuzzing

```bash
go test -fuzz=FuzzParseRequest -fuzztime=30s ./tsp/
go test -fuzz=FuzzHandleHTTP -fuzztime=30s ./server/
```
