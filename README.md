# QuantumHello

QuantumHello checks whether a host can negotiate TLS 1.3 with a supported ML-KEM hybrid, including `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`.

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
- `GET /healthz`
- `GET /readyz`
