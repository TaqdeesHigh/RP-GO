# Go Reverse Proxy Server

A powerful and extensible reverse proxy server written in Go. Supports dynamic route mapping, IP blacklisting, per-IP rate limiting, HTTPS, and real-time request metrics.

---

## Features

- Path-based reverse proxy routing
- TLS/HTTPS support
- Per-IP rate limiting
- IP blacklisting (with optional expiration)
- JSON-based configuration
- Logging to file or stdout
- Periodic automatic config and blacklist saving
- Real-time request metrics tracking
- Graceful shutdown with cleanup

---

## Installation

1. **Install Go (1.18+)**  
   [Download and install Go](https://go.dev/doc/install)

2. **Clone the repository and build**

   ```bash
   git clone https://github.com/yourusername/go-reverse-proxy.git
   cd go-reverse-proxy
   go build -o reverse-proxy main.go
   ```

---

## Running the Proxy

You can run the proxy using command-line flags or a config file:

```bash
go run main.go [flags]
```

### Optional Flags:

| Flag         | Description                         |
|--------------|-------------------------------------|
| -config      | Path to JSON config file            |
| -listen      | Listening address (e.g., :8080)     |
| -target      | Default target URL                 |
| -log         | Log file path                      |
| -blacklist   | Blacklist file path                |
| -cert        | TLS certificate file               |
| -key         | TLS private key file               |
| -rate        | Max requests per minute per IP     |
| -metrics     | Enable or disable metrics (true/false) |

Example:

```bash
go run main.go -listen ":443" -target "http://localhost:8000" -cert cert.pem -key key.pem -rate 100
```

---

## Configuration File (`proxy.properties.json`)

Example:

```json
{
  "listenAddr": ":8080",
  "targetURL": "http://localhost:8000",
  "logFile": "proxy.log",
  "blacklistFile": "blacklist.json",
  "certFile": "cert.pem",
  "keyFile": "key.pem",
  "requestsPerMin": 60,
  "enableMetrics": true,
  "routes": [
    {
      "pathPrefix": "/api",
      "targetURL": "http://localhost:3001"
    },
    {
      "pathPrefix": "/static",
      "targetURL": "http://localhost:3002"
    }
  ]
}
```

- `routes`: Defines prefix-based routing (longer prefixes have higher priority).
- `targetURL`: Fallback target if no route matches.
- TLS is enabled if both `certFile` and `keyFile` are provided.

---

## Metrics

If `enableMetrics` is set to `true`, the proxy tracks:

- Total requests
- Response status codes
- Request methods
- Rate limit rejections
- Blacklisted rejections
- Average response time

> Metrics are not currently exposed via API but are stored in memory and logs.

---

## Blacklist System

Blacklist entries are stored in `blacklist.json`:

```json
[
  {
    "ip": "192.168.1.50",
    "reason": "suspicious activity",
    "created_at": "2025-04-10T14:30:00Z",
    "expires_at": "2025-04-11T14:30:00Z"
  }
]
```

- Expired entries are automatically ignored on load.
- IPs can be blacklisted via code (`BlacklistIP`) and removed via (`RemoveFromBlacklist`).

---

## Path Routing

Use `AddRoute(pathPrefix, targetURL)` to define routes:

```go
proxy.AddRoute("/blog", "http://localhost:8081")
proxy.AddRoute("/auth", "http://localhost:9000")
```

- Routes are prioritized by longest prefix match.

---

## TLS Support

To enable HTTPS, provide the following flags or config options:

```bash
go run main.go -cert cert.pem -key key.pem
```

The server will automatically switch to `ListenAndServeTLS`.

---

## Testing Tips

- Send `X-Test-Skip-Rate-Limit: true` to bypass rate limiting in tests.
- Add `X-Real-IP` or `X-Forwarded-For` headers to simulate client IPs.

---

## Logs

- If `logFile` is specified, logs are saved to that file.
- Otherwise, logs are printed to `stdout`.

---

## Files Created

| File                  | Purpose                 |
|-----------------------|-------------------------|
| proxy.properties.json | Configuration           |
| blacklist.json        | Blacklisted IPs         |
| proxy.log (optional)  | Logging output          |

---

## Author

**Taqdees**

