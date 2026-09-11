# QuantumHello

QuantumHello assesses a host's post-quantum TLS readiness. It checks TLS 1.3 ML-KEM hybrids including `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`, then reports a readiness grade and supporting evidence.

Grades range from `excellent` to `failed`. The new `grade` and `assessment` fields are the recommended API interface; `status` is retained as a legacy compatibility field.

## Authentication evidence

QuantumHello keeps three related TLS observations distinct:

- The certificate's public key (for example, an ML-DSA authentication key).
- The signatures on the certificate chain (for example, ML-DSA or SLH-DSA).
- The TLS 1.3 `CertificateVerify` signature sent during the handshake.

The checker currently reports the certificate public key and certificate-chain
signatures, and a successful handshake confirms that the server authenticated
with its private key. Go's public `crypto/tls` API does not expose the exact
peer `CertificateVerify` signature scheme, so QuantumHello does not claim to
identify that scheme independently yet. Adding that observation requires a
lower-level or instrumented TLS implementation and is deferred for now.

## Run locally

```bash
go run ./cmd/web
```

Check a host from the command line:

```bash
go run ./cmd/web --check cloudflare.com
```

## OQS interoperability test

The opt-in live test exercises a curated set of classical and ML-DSA points
published by the Open Quantum Safe interoperability server, including its
non-443 ports. It does not change the production checker’s port restriction.

```bash
go test -tags=live ./internal/probe -run TestOQSLiveMatrix -timeout=2m
```

The live test requires Internet access and is intentionally excluded from
ordinary `go test ./...` runs.

## HTTP endpoints

- `GET /`
- `POST /check`
- `GET /api/check?url=example.com`
- `GET /api/check?url=example.com&pretty=1` (pretty-printed JSON)
- `GET /api/check?url=example.com&download=1` (downloadable JSON attachment)
- `GET /healthz`
- `GET /readyz`
