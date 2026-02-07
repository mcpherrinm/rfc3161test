# rfc3161test

This is an experiment at building an RFC 3161 Time-Stamp Authority (TSA) server in Go.

It is not trustworthy, and should not be used. Other than this human-written warning, it is written by AI.

The server accepts DER-encoded `TimeStampReq` messages over HTTP and returns DER-encoded `TimeStampResp` messages, as specified in [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) §3.4.

The implementation includes [RFC 5816](https://www.rfc-editor.org/rfc/rfc5816) support: the `SigningCertificateV2` attribute with `ESSCertIDv2` is included in the CMS `SignedData` signed attributes, identifying the TSA certificate using SHA-256.

## Building

```bash
go build ./...
```

## Generating a TSA key and certificate

```bash
go run ./cmd/tsakeygen -key tsa.key -cert tsa.crt
```

This creates a 3072-bit RSA private key (`tsa.key`) and a self-signed certificate (`tsa.crt`) suitable for the TSA server. The certificate includes the `id-kp-timeStamping` extended key usage (critical) per the CA/Browser Forum Code Signing Baseline Requirements. Use `-bits` to change the key size (minimum 3072 per CSBR §6.1.5.2).

## Running the server

Start the server with the generated key and certificate:

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
