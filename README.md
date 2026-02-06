# rfc3161test

A reference implementation of an RFC 3161 Time-Stamp Authority (TSA) server in Go, using only the standard library.

The server accepts DER-encoded `TimeStampReq` messages over HTTP and returns DER-encoded `TimeStampResp` messages, as specified in [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) §3.4.

## Building

```bash
go build ./...
```

## Running the server

Generate a TSA key and certificate, then start the server:

```bash
go run ./cmd/tsserver -key tsa.key -cert tsa.crt -addr :3161
```

## Requesting a timestamp

```bash
go run ./cmd/tsclient -server http://localhost:3161 -file document.txt -hash sha256
```

## Testing

```bash
go test -race ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for linting and fuzzing instructions.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details and implementation phases.
