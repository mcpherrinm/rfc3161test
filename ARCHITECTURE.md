# RFC 3161 Time-Stamp Server — Architecture & Project Plan

## Overview

An HTTP-based Time-Stamp Authority (TSA) server implementing RFC 3161 (Internet X.509 PKI Time-Stamp Protocol) in Go, using only the standard library. The server accepts DER-encoded `TimeStampReq` messages over HTTP and returns DER-encoded `TimeStampResp` messages, as specified in RFC 3161 §3.4.

## Constraints

- **Go standard library only** — no third-party modules.
- **golangci-lint** for static analysis.
- **GitHub Actions** for CI (build, test, lint, fuzz).
- Code brevity: minimal comments, no unnecessary checks or tests.

## Package Structure

```
rfc3161test/
├── asn1/           # DER encoding/decoding helpers beyond encoding/asn1
├── tsp/            # RFC 3161 types and logic
│   ├── request.go  # TimeStampReq parsing and validation
│   ├── response.go # TimeStampResp / TSTInfo construction
│   └── oid.go      # OID constants (hash algorithms, id-ct-TSTInfo, policy)
├── server/         # HTTP handler and server wiring
│   └── handler.go  # POST handler: application/timestamp-query → application/timestamp-reply
├── cmd/
│   ├── tsserver/
│   │   └── main.go # Server entry point: flags, key loading, listen
│   └── tsclient/
│       └── main.go # Client CLI: build and POST a TimeStampReq, print result
├── .github/
│   └── workflows/
│       └── ci.yml  # GitHub Actions: build, test, fuzz, lint
├── go.mod
├── rfc3161.txt     # Reference specification
└── ARCHITECTURE.md # This file
```

## Core Components

### 1. ASN.1 / DER Layer (`asn1/`)

Go's `encoding/asn1` handles most DER work. This package provides any supplementary helpers needed for:

- Encoding/decoding BIT STRING values for `PKIFailureInfo` (bit-indexed, not byte-indexed).
- Building CMS `ContentInfo` / `SignedData` structures that wrap `TSTInfo`.
- Encoding `GeneralizedTime` with sub-second precision and DER rules (no trailing zeros, mandatory `Z` suffix).

### 2. TSP Types & Logic (`tsp/`)

**request.go** — Parse and validate `TimeStampReq`:

```
TimeStampReq ::= SEQUENCE {
    version          INTEGER {v1(1)},
    messageImprint   MessageImprint,
    reqPolicy        OBJECT IDENTIFIER OPTIONAL,
    nonce            INTEGER           OPTIONAL,
    certReq          BOOLEAN DEFAULT FALSE,
    extensions       [0] IMPLICIT Extensions OPTIONAL
}
```

Validation rules:
- `version` must be 1.
- `hashAlgorithm` OID must be recognized (SHA-256, SHA-384, SHA-512); reject with `badAlg` otherwise.
- `hashedMessage` length must match the algorithm's output size; reject with `badDataFormat` otherwise.
- Extensions, if present and unrecognized, reject with `unacceptedExtension`.
- Requested policy, if present and not the server's policy, reject with `unacceptedPolicy`.

**response.go** — Build `TimeStampResp`:

```
TimeStampResp ::= SEQUENCE {
    status          PKIStatusInfo,
    timeStampToken  TimeStampToken OPTIONAL
}
```

On success (`status = granted`):
1. Construct `TSTInfo` with server policy OID, echoed `messageImprint`, monotonic `serialNumber`, `genTime` (current UTC), and echoed `nonce` if present.
2. DER-encode `TSTInfo`.
3. Wrap in CMS `SignedData` (`eContentType = id-ct-TSTInfo`), sign with the TSA's RSA/ECDSA private key.
4. Wrap `SignedData` in `ContentInfo`.
5. If `certReq` is true, include the TSA certificate in `SignedData.certificates`.

On failure, return `PKIStatusInfo` with appropriate `PKIFailureInfo` bit and no token.

**oid.go** — OID constants:

| Name | OID |
|------|-----|
| `id-ct-TSTInfo` | 1.2.840.113549.1.9.16.1.4 |
| `id-signedData` | 1.2.840.113549.1.7.2 |
| SHA-256 | 2.16.840.1.101.3.4.2.1 |
| SHA-384 | 2.16.840.1.101.3.4.2.2 |
| SHA-512 | 2.16.840.1.101.3.4.2.3 |
| TSA policy | 1.2.3.4.1 (configurable) |

### 3. HTTP Server (`server/`)

Single endpoint: `POST /`

Request handling:
1. Verify `Content-Type: application/timestamp-query`.
2. Read body (limit to reasonable max, e.g., 64 KiB).
3. DER-decode `TimeStampReq`.
4. Validate request fields.
5. Build `TimeStampResp`.
6. Write response with `Content-Type: application/timestamp-reply`.

Error cases:
- Wrong HTTP method → 405.
- Wrong content type → 400.
- Malformed DER → return `TimeStampResp` with `badDataFormat`.

### 4. Entry Point — Server (`cmd/tsserver/`)

- Load TSA private key and certificate from PEM files (paths via flags).
- Bind to configurable address (default `:3161`).
- Start HTTP server.

### 5. Entry Point — Client (`cmd/tsclient/`)

Command-line tool that builds and sends a `TimeStampReq`:

- Accept flags: server URL, file to hash (or raw hash), hash algorithm.
- Hash the input with the selected algorithm.
- Construct a DER-encoded `TimeStampReq` with a random nonce.
- POST to the server with `Content-Type: application/timestamp-query`.
- Decode the `TimeStampResp`, verify status, and print the result.

## Serial Number Uniqueness

An atomic `int64` counter, starting from 1, incremented per token issued. Per RFC: "the property MUST be preserved even after a possible interruption." For this implementation, the counter resets on restart — acceptable for a reference server. A production server would persist to disk.

## Testing Strategy

### Unit Tests (`*_test.go` alongside each package)

| Area | Tests |
|------|-------|
| Request parsing | Valid v1 request; wrong version; unknown hash OID → `badAlg`; hash length mismatch → `badDataFormat`; unrecognized extension → `unacceptedExtension`; wrong policy → `unacceptedPolicy` |
| Response building | Granted response round-trip; nonce echo; serial number increments; `certReq` true includes cert; `certReq` false omits cert |
| TSTInfo fields | `genTime` format correctness; policy matches; messageImprint echoed |
| CMS/SignedData | Signature verifies with TSA public key; `eContentType` is `id-ct-TSTInfo` |
| PKIFailureInfo | Correct bit positions for each failure code |

### Integration Tests (`server/handler_test.go`)

Use `net/http/httptest.Server` to run the full HTTP flow:

- POST valid request → 200, `application/timestamp-reply`, granted response, valid signature.
- POST with wrong content type → 400.
- GET request → 405.
- POST garbage bytes → response with `badDataFormat`.
- POST request with unsupported hash → response with `badAlg`.

Integration test as client:
- Build a `TimeStampReq`, POST to test server, decode `TimeStampResp`, verify `TSTInfo` fields match request, verify CMS signature.

### End-to-End Test (`cmd/integration_test.go`)

A test that exercises the server and client binaries together:

1. Generate an ephemeral TSA key + certificate.
2. Start `cmd/tsserver` as an in-process `httptest` server.
3. Run the client logic against the running server with a test file.
4. Verify the client receives a valid timestamp response.
5. Verify the response contains correct nonce, policy, and message imprint.

### Fuzz Tests (`*_fuzz_test.go`)

Fuzz all input parsing surfaces:

| Target | Function |
|--------|----------|
| `FuzzParseRequest` | Feed random bytes to `tsp.ParseRequest` — must not panic. |
| `FuzzHandleHTTP` | Feed random body to HTTP handler — must return valid HTTP response, must not panic. |

Fuzz tests use `testing.F` with seed corpus of:
- A valid DER-encoded `TimeStampReq`.
- An empty input.
- A truncated valid request.

### Test Helpers

- `testutil` functions to generate an ephemeral RSA key + self-signed certificate for tests.
- Helper to build a valid `TimeStampReq` for reuse across tests.

## CI Configuration (`.github/workflows/ci.yml`)

```yaml
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - run: go build ./...
      - run: go test -race ./...
      - run: go test -fuzz=FuzzParseRequest -fuzztime=30s ./tsp/
      - run: go test -fuzz=FuzzHandleHTTP -fuzztime=30s ./server/
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - uses: golangci/golangci-lint-action@v6
```

## Implementation Phases

### Phase 0: Project Scaffolding & CI
- Initialize Go module (`go.mod`).
- Create package directory structure (`asn1/`, `tsp/`, `server/`, `cmd/tsserver/`, `cmd/tsclient/`) with placeholder files so the project compiles.
- Add `.github/workflows/ci.yml` with build, test, and golangci-lint jobs.
- Add `.golangci.yml` configuration.
- Verify CI runs green on the scaffolding before writing any logic.

### Phase 1: ASN.1 Types & Request Parsing
- Define Go structs mapping to RFC 3161 ASN.1 types.
- Implement `ParseRequest` using `encoding/asn1.Unmarshal`.
- Validate version, hash algorithm, hash length.
- Unit tests + fuzz test for parsing.

### Phase 2: Response Building & CMS Signing
- Implement `TSTInfo` construction and DER encoding.
- Build CMS `SignedData` wrapper using `crypto/x509` and `crypto/rsa` or `crypto/ecdsa`.
- Implement `PKIStatusInfo` for success and failure cases.
- Unit tests for response construction and signature verification.

### Phase 3: HTTP Server & Client CLI
- Implement HTTP handler with content-type checks and body size limit.
- Wire up to `cmd/tsserver/main.go`.
- Implement `cmd/tsclient/main.go` for requesting timestamps from the command line.
- Integration tests with `httptest`.
- End-to-end integration test running server and client together.
- Fuzz test for HTTP handler.

### Phase 4: Polish
- Final lint and CI check.
- Review for code brevity and RFC compliance.

## Key Design Decisions

1. **Standard library only**: CMS `SignedData` construction is done manually using `encoding/asn1` + `crypto` packages rather than an external PKCS#7 library.
2. **RSA with SHA-256 for signing**: The TSA signs tokens with RSA PKCS#1 v1.5 + SHA-256. ECDSA support is straightforward to add later.
3. **No persistence**: Serial numbers are in-memory. Acceptable for a reference/test implementation.
4. **Minimal error surface**: Unrecognized extensions and policies are cleanly rejected per RFC requirements. No optional features beyond nonce support.
