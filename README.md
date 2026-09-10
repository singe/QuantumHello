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

## HTTP endpoints

- `GET /`
- `POST /check`
- `GET /api/check?url=example.com`
- `GET /api/check?url=example.com&pretty=1` (pretty-printed JSON)
- `GET /api/check?url=example.com&download=1` (downloadable JSON attachment)
- `GET /healthz`
- `GET /readyz`
