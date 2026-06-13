# QuantumHello

QuantumHello checks whether a host can negotiate TLS 1.3 with `X25519MLKEM768`.

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
