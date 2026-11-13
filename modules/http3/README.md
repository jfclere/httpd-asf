# mod_http3: HTTP/3 & QUIC for Apache HTTP Server

`mod_http3` adds support for the **HTTP/3** protocol ([RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114)) running over the **QUIC** transport protocol ([RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)) to the Apache HTTP Server.

HTTP/3 runs over UDP rather than TCP and integrates TLS 1.3 encryption natively inside QUIC, eliminating TCP head-of-line blocking and providing faster connection establishment (0-RTT / 1-RTT).

> **Experimental Notice:** `mod_http3` is currently experimental and intended for testing and development. Performance is being actively optimized, and OpenSSL's own QUIC server (`--with-http3-quic=openssl`) is slower and less complete than the default ngtcp2 transport; do not use it in critical production environments yet.

---

## Architecture & Dependencies

`mod_http3` relies on:
1. **[libnghttp3](https://nghttp2.org/nghttp3/)** (>= 1.0.0): Handles HTTP/3 framing and QPACK header compression ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204)).
2. A QUIC transport, chosen when building with `--with-http3-quic`:
   - `ngtcp2` (default): **[libngtcp2](https://github.com/ngtcp2/ngtcp2)** (>= 1.22.1) with its `libngtcp2_crypto_ossl` helper runs the QUIC transport, and **OpenSSL** (with the QUIC TLS API) only performs the TLS 1.3 handshake. Supports 0-RTT (`H3EarlyData`), routing of packets by connection ID across child processes and connection migration.
   - `openssl`: **OpenSSL** 3.5 or later runs the whole QUIC transport with its own QUIC server. No ngtcp2 is needed, but there is no 0-RTT (`H3EarlyData` is refused), no routing by connection ID (one UDP socket is used) and no connection migration (see [`QUIC_CONNECTION_MIGRATION.md`](QUIC_CONNECTION_MIGRATION.md)).

---

## Build Instructions

### Prerequisites

Ensure you have OpenSSL (with QUIC support enabled), `libnghttp3` and, for the default transport, `libngtcp2` with `libngtcp2_crypto_ossl` installed on your system.

### Configuration

To build `mod_http3`, add `--enable-http3` to your `httpd` `./configure` command:

```bash
./configure --enable-ssl --enable-http2 --enable-http3 [other options...]
```

If `libnghttp3` is installed in a non-standard location:

```bash
./configure --enable-http3 --with-nghttp3=/path/to/nghttp3 [other options...]
```

If `libngtcp2` is installed in a non-standard location:

```bash
./configure --enable-http3 --with-ngtcp2=/path/to/ngtcp2 [other options...]
```

To run QUIC on OpenSSL's own QUIC server (OpenSSL 3.5 or later) instead of ngtcp2:

```bash
./configure --enable-http3 --with-http3-quic=openssl [other options...]
```

If `pkg-config` is available on your system, `libnghttp3.pc` and `libngtcp2.pc` will be automatically detected via `PKG_CONFIG_PATH`.

---

## Basic Configuration

### 1. Enable Modules and Protocols

To enable HTTP/3 alongside HTTP/2 and HTTP/1.1:

```apache
LoadModule ssl_module   modules/mod_ssl.so
LoadModule http3_module modules/mod_http3.so

# Listen on both TCP (for HTTPS/Alt-Svc) and UDP (for QUIC)
Listen 4433 https

<VirtualHost *:4433>
    ServerName example.com

    SSLEngine on
    SSLCertificateFile    conf/server.crt
    SSLCertificateKeyFile conf/server.key

    # Enable HTTP/3, HTTP/2, and HTTP/1.1
    Protocols h3 h2 http/1.1

    DocumentRoot /var/www/html

</VirtualHost>
```

### 2. Client Discovery via `Alt-Svc`

Because HTTP/3 runs over UDP, web browsers typically connect via TCP (HTTP/1.1 or HTTP/2) first. `mod_http3` automatically injects the `Alt-Svc` header into responses:

```http
Alt-Svc: h3=":4433"; ma=86400; persist=1
```

Browsers caching this header will switch to HTTP/3 over QUIC on subsequent requests.

---

## Configuration Directives

| Directive | Default | Context | Description |
| :--- | :--- | :--- | :--- |
| `H3Port` | *Server Port* | `server config`, `virtual host` | UDP port to listen on for QUIC/HTTP-3. |
| `H3AltSvc` | `on` | `server config`, `virtual host` | Advertise HTTP/3 support via the `Alt-Svc` response header. |
| `H3AltSvcMaxAge` | `86400` | `server config`, `virtual host` | `max-age` in seconds for the `Alt-Svc` header advertisement. |
| `H3MaxConnections` | `256` | `server config` | Maximum concurrent QUIC/HTTP-3 connections per child process. |
| `H3MaxConcurrentStreams` | `100` | `server config`, `virtual host` | Maximum concurrent active streams per connection. |
| `H3StreamBufferSize` | `65536` | `server config`, `virtual host` | Per-stream request and streaming-response buffer size (bytes). |
| `H3MaxRequestBodySize` | `10485760` (10MB) | `server config`, `virtual host` | Maximum request body size buffered in memory (bytes). |
| `H3MaxResponseBodySize` | `0` (unlimited) | `server config`, `virtual host` | Maximum response body size for whole-response buffering. |
| `H3HandshakeTimeout` | `10` | `server config` | Timeout in seconds for QUIC TLS handshakes. |
| `H3IdleTimeout` | `300` | `server config` | Idle timeout in seconds before closing inactive QUIC connections. |
| `H3StreamTimeout` | *Server Timeout* | `server config`, `virtual host` | Timeout in seconds without progress before aborting a stream. |
| `H3AddressValidation` | `on` | `server config` | Validate client addresses using QUIC Retry packets before accept. |
| `H3SessionTickets` | `on` | `server config` | Issue TLS 1.3 session tickets for fast connection resumption. |
| `H3EarlyData` | `off` | `server config` | Accept 0-RTT request data on resumed connections; unsafe methods wait for the handshake. Not available with `--with-http3-quic=openssl`. |
| `H3SocketBufferSize` | `2097152` (2MB) | `server config` | Socket send and receive buffer sizes for the UDP listener. |
| `H3MaxStreamErrors` | `8` | `server config`, `virtual host` | Stream errors allowed before terminating connection with `H3_EXCESSIVE_LOAD`. |
| `H3QpackTableCapacity` | `4096` | `server config`, `virtual host` | QPACK dynamic table capacity in bytes (`0` disables dynamic table). |
| `H3QpackBlockedStreams` | `0` | `server config`, `virtual host` | Allowed QPACK blocked streams count. |
| `H3MinWorkers` | `16` | `server config` | Minimum request worker threads per child process. |
| `H3MaxWorkers` | `64` | `server config` | Maximum request worker threads per child process. |
| `H3MaxWorkerIdleSeconds`| `600` | `server config` | Seconds an idle worker thread is kept before termination. |

---

## Status Handler

You can inspect HTTP/3 runtime status by enabling the `http3-status` handler:

```apache
<Location /http3-status>
    SetHandler http3-status
    Require local
</Location>
```

---

## Testing & Verification

### Using `curl` (with HTTP/3 support)

```bash
# Direct HTTP/3 connection
curl --http3 -v https://localhost:4433/

# Test Alt-Svc upgrade
curl --alt-svc /tmp/altsvc.cache -v https://localhost:4433/
```

### Using Web Browsers

- **Google Chrome**: Launch with `--origin-to-force-quic-on=localhost:4433` or ensure valid certificates and reload after receiving the `Alt-Svc` header.
- **Mozilla Firefox**: Enable HTTP/3 in `about:config` (`network.http.http3.enable = true`).

---

## Current Limitations & Notes

- **Multi-Process UDP Listener**: In standard multi-process MPMs, one child process manages the UDP listening socket while others coordinate in the background.
- **Connection Migration**: QUIC connection migration (RFC 9000 §9) works with the `ngtcp2` transport. With `--with-http3-quic=openssl` it is limited by the OpenSSL QUIC stack (see [`QUIC_CONNECTION_MIGRATION.md`](QUIC_CONNECTION_MIGRATION.md)).
- **TLS Certificates**: Modern browsers reject self-signed or invalid certificates for HTTP/3 more strictly than for HTTP/1.1 or HTTP/2. Use trusted certificates or valid local CA certificates during testing.
