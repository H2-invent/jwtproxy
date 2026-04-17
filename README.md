# Reverse Proxy with JWT Authentication

A reverse proxy which validates incoming requests using a shared HMAC secret (HS256).
Requests are rejected if:

* No token is provided (neither `?token=` query parameter nor `Authorization: Bearer` header).
* The token is invalid, expired, or signed with the wrong secret.
* The `path` claim in the token does not exactly match the request path.

## How it works

```
Client  ──→  jwtproxy (port 8080)  ──→  Backend (internal only)
              │
              ├─ validate token (HS256 + expiry)
              ├─ check token path == request path
              └─ strip ?token= before forwarding
```

## Token format

Tokens must be signed with **HS256** and contain at minimum:

```json
{
  "exp": 1735689600,
  "path": "/your/request/path"
}
```

| Claim  | Required | Description |
|--------|----------|-------------|
| `exp`  | ✅       | Expiry timestamp (Unix). Expired tokens are always rejected. |
| `path` | ✅       | The exact request path this token grants access to. |

The token path must **exactly** match the request path — `/test/abc` and `/test/abc/` are treated as different paths.

## Passing the token

**Option 1 – Query parameter (recommended for browser/Etherpad links):**
```
GET /test/abc?token=eyJ...
```
The `?token=` parameter is stripped before the request is forwarded to the backend.

**Option 2 – Authorization header:**
```
Authorization: Bearer eyJ...
```

## Configuration

Configuration can be provided via command line flags or environment variables.

| Environment variable         | Flag                | Description |
|------------------------------|---------------------|-------------|
| `JWTPROXY_SECRET`            | `-secret`           | **Required.** Shared HMAC secret for validating tokens. |
| `JWTPROXY_REMOTE_URL`        | `-remoteURL`        | **Required.** Backend URL to proxy requests to. |
| `JWTPROXY_LISTEN_PORT`       | `-port`             | Port to listen on (default: `9090`). |
| `JWTPROXY_REMOTE_HOST_HEADER`| `-remoteHostHeader` | Override the `Host` header sent to the backend. |
| `JWTPROXY_HEALTHCHECK_URI`   | `-health`           | Health check endpoint (default: `/health`). |
| `JWTPROXY_PREFIX`            | `-prefix`           | URL prefix to strip before forwarding, e.g. `/api`. |

## Running

### Command line

```bash
JWTPROXY_SECRET=my-secret \
JWTPROXY_REMOTE_URL=http://localhost:9001 \
JWTPROXY_LISTEN_PORT=8080 \
./jwtproxy
```

### Docker (standalone)

```bash
docker run -p 8080:8080 \
  -e JWTPROXY_SECRET=my-secret \
  -e JWTPROXY_REMOTE_URL=http://backend:9001 \
  -e JWTPROXY_LISTEN_PORT=8080 \
  ghcr.io/your-org/jwtproxy
```

### Docker (bundled with Etherpad)

The provided `Dockerfile` extends `etherpad/etherpad` and runs both processes inside one container. Etherpad is bound to `127.0.0.1:9001` (not exposed), jwtproxy listens on `0.0.0.0:8080`.

```bash
docker build -t etherpad-jwt .

docker run -p 8080:8080 \
  -e JWTPROXY_SECRET=my-secret \
  -e ADMIN_PASSWORD=etherpad-admin \
  etherpad-jwt
```

## Generating a token

Using [jwt.io](https://jwt.io) or any JWT library. Example with Python:

```python
import jwt, time

token = jwt.encode(
    {"exp": int(time.time()) + 3600, "path": "/p/my-pad"},
    "my-secret",
    algorithm="HS256",
)
print(token)
```

Then access the pad:
```
https://your-host/p/my-pad?token=eyJ...
```

## Health check

The proxy responds with HTTP 200 at `/health` (configurable via `JWTPROXY_HEALTHCHECK_URI`). Health check requests bypass token validation.

## Building from source

```bash
go build -o jwtproxy .
```

Requires Go 1.25+.