# QuantumHello

QuantumHello assesses a host's post-quantum TLS readiness. It checks TLS 1.3 ML-KEM hybrids including `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`, then reports a readiness grade and supporting evidence.

Grades range from `excellent` to `failed`. The new `grade` and `assessment` fields are the recommended API interface; `status` is retained as a legacy compatibility field.

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
