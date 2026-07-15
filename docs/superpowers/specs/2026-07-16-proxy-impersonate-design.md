# Proxy::Impersonate -- design

**Status:** approved design; Task-1 spike done -> revised (see below)
**Date:** 2026-07-16
**Program:** sub-project 2 of 3 in the EV::WebKit network-fingerprint-defeat program
(sub-project 1 `Curl::Impersonate` is DONE; sub-project 3 is the EV::WebKit wiring).

## Post-spike revision (2026-07-16)

The Task-1 spike proved WebKitGTK's glib-networking/GnuTLS build honors **neither**
`SSL_CERT_FILE` **nor** `SSL_CERT_DIR`, so a root CA cannot be trusted that way.
Trust therefore uses the pre-decided fallback: **`set_tls_errors_policy(IGNORE)`**
on the `WebKitNetworkSession` (set by sub-project 3 on the WebKit side).

Because `IGNORE` makes WebKit accept any presented cert, the CA + per-host-leaf +
bundle machinery below is **dropped** in favour of a **single persisted
self-signed cert** presented for every host. This supersedes the "TLS termination
and cert minting" and "risk #1" sections wherever they describe a CA, per-host
leaf minting, an SNI callback, `bundle.pem`, `ca_bundle_path`, or `SSL_CERT_FILE`.
Security is unchanged: the WebKit<->proxy hop is localhost, and Curl::Impersonate
still verifies upstream. Net::SSLeay is still used, now only to generate one
self-signed server cert. The daemon config gains `cert_dir` (persist the cert) and
no longer reports `ca_bundle_path`.

## Goal

A standalone EV-based TLS-terminating MITM proxy that lets EV::WebKit present a
chosen real browser's **connection** fingerprint (TLS JA3/JA4 + HTTP/2 Akamai) to
origin servers. WebKit points its proxy setting at the daemon; the daemon
terminates WebKit's TLS with a locally-trusted CA, reads the plaintext HTTP
request, and re-originates it upstream through `Curl::Impersonate` (patched
curl + BoringSSL), so the origin sees Chrome (or whichever target), not WebKit's
GnuTLS stack.

## Scope

**v1 (this spec):** HTTP and HTTPS-via-CONNECT, HTTP/1.1 on the WebKit hop,
h1/h2 upstream, incremental response streaming, keep-alive.

**Deferred (non-goals for v1):** WebSockets, HTTP/3 upstream, streaming *request*
uploads, EC-P256 leaf certs (perf), wildcard leaf certs, a `bin/` CLI.

## Architecture and data flow

`Proxy::Impersonate` is a standalone dist that runs its own EV loop as a
companion process. EV::WebKit sets `set_proxy => 'http://127.0.0.1:PORT'` and
uses it as an HTTP/HTTPS forward proxy.

```
WebKit --set_proxy(http://127.0.0.1:PORT)--> Proxy::Impersonate --> origin
        |                                     |                       ^
  HTTP : absolute-URI request                 |  Curl::Impersonate    |
  HTTPS: CONNECT host:443, then TLS to "host"  |  (target: JA3/JA4/    |
         proxy presents minted leaf-for-host   |   Akamai, verify=on)  |
         (CA-signed, trusted via SSL_CERT_FILE)-+                       |
```

Per request:
1. WebKit connects to the proxy on localhost (its own h1 + TLS-to-localhost; the
   origin never sees this hop).
2. Plain HTTP: WebKit sends an absolute-URI request; read directly.
   HTTPS: WebKit sends `CONNECT host:443`; proxy replies `200`, then terminates
   WebKit's TLS with a per-host leaf cert minted on the fly and signed by the
   proxy's root CA.
3. The proxy has the plaintext request. It forwards it through
   `Curl::Impersonate::Multi` (the EV-drivable async handle from sub-project 1)
   with the configured target and `verify=on` upstream.
4. The origin sees the target browser's TLS + HTTP/2 fingerprint; the response
   streams back to WebKit over the terminated connection.

One EV loop drives everything: an accept watcher, per-connection io watchers for
the WebKit side, and `Curl::Impersonate::Multi`'s socket-action watchers for the
upstream side.

## Components (files)

Four focused, independently testable units:

- **`lib/Proxy/Impersonate.pm`** -- daemon/orchestrator. Constructor
  (`impersonate`, `listen`, `ca_dir`, `timeout`, `verify`, `follow_redirects`),
  EV accept watcher, the shared `Curl::Impersonate::Multi`, `run`/`stop`. Owns
  the loop; wires the other three together. Reports `port`, `ca_bundle_path`.
- **`lib/Proxy/Impersonate/CA.pm`** -- crypto (Net::SSLeay). Generates/loads a
  persisted root CA in `ca_dir`; mints + caches per-host leaf certs signed by it;
  writes `bundle.pem` (system CAs + our CA). Exposes `ca_bundle_path` and
  `leaf_for($host) -> ($cert, $key)`.
- **`lib/Proxy/Impersonate/Connection.pm`** -- per-WebKit-connection state
  machine. Raw read -> handle `CONNECT` -> Net::SSLeay server handshake (driven
  by EV want-read/want-write) -> parse request -> forward via the shared Multi ->
  stream response back. One object per accepted socket; holds its io watcher.
- **`lib/Proxy/Impersonate/HTTP.pm`** -- pure functions: parse an HTTP/1.x
  request head (method, target, headers, body framing via Content-Length /
  chunked) and serialize a response head. No sockets; unit-testable on byte
  strings.

**Dependencies:** `EV`, `Net::SSLeay`, `Curl::Impersonate` (>= the version that
adds the streaming callbacks below).

## TLS termination and cert minting (Net::SSLeay)

**Root CA** (generated once, persisted in `ca_dir`): self-signed RSA-2048
(`CA:TRUE`, `keyCertSign`), stored as `ca.crt` / `ca.key` (key `0600`). RSA-2048
for universal GnuTLS/WebKit acceptance. `CA.pm` also writes `bundle.pem` =
system CA bundle + our `ca.crt`; that path is what `SSL_CERT_FILE` points WebKit
at. Because every WebKit connection is proxied and therefore only ever sees a
leaf signed by our CA, our CA alone is sufficient for the proxy path; the system
CAs are included as belt-and-suspenders so any connection that legitimately
bypasses the proxy (a `set_proxy` ignore host, or a deferred WebSocket/h3 path)
still validates. The system bundle is located by probing `$ENV{SSL_CERT_FILE}`
then the common distro paths (e.g. `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt`); if none is found, `bundle.pem` contains just
our CA and a diagnostic is logged.

**Per-host leaf** (minted on demand, cached by host): RSA-2048, `CN=host` **and**
`subjectAltName=DNS:host` (modern TLS ignores CN; the SAN is mandatory), signed
by the CA with SHA-256, short validity. Cached in memory keyed by host -- leaf
generation is the one CPU cost, so the cache matters for a browser opening many
hosts.

**Handshake** (per connection, EV-driven): one server `SSL_CTX` with a TLS SNI
callback (`SSL_CTX_set_tlsext_servername_callback`) that looks up / mints
`leaf_for(SNI)` and installs it on the `SSL` -- arbitrary hosts without
pre-registration. The CONNECT target host is the fallback when a client sends no
SNI. The socket is non-blocking; `SSL_accept` is pumped through `WANT_READ` /
`WANT_WRITE` by arming the connection's EV io watcher.

## Request handling and header coherence

After termination (HTTPS) or directly (HTTP), parse the HTTP/1.x request and
reconstruct the absolute URL -- `https://<host>/<path>` from the CONNECT/SNI host
for tunneled requests, or the absolute-form target for plain HTTP. Body framing
follows Content-Length or chunked.

Header coherence (HTTP/2 header **order** is itself part of the Akamai
fingerprint):
- Forward through `Curl::Impersonate` with `default_headers=1`, so the origin
  sees the target's exact header set and order.
- Overlay the request-specific state WebKit carries: `Cookie`, `Referer`,
  `Origin`, `Content-Type`, `Authorization`, and the body.
- Drop what the target template already owns or what identifies WebKit/the hop:
  `User-Agent`, `Accept*`, `sec-ch-ua*`, `Connection`, `Proxy-*`,
  `Upgrade-Insecure-Requests` -- the target's win.

Exact allow/drop lists are pinned with a test during implementation.

## Response streaming (extends sub-project 1)

Response bodies stream to WebKit as they arrive. This requires an extension to
`Curl::Impersonate::Multi` (a prerequisite task in the plan):
- `on_headers($status, \%headers)` -- fired once when upstream response headers
  are known.
- `on_body($chunk)` -- fired per body chunk, with backpressure: pause upstream
  via `curl_easy_pause(CURLPAUSE_RECV)` when WebKit's write buffer is full.
- `resume` -- `curl_easy_pause(CURLPAUSE_CONT)` when WebKit's socket drains.
- `on_done($err)` -- completion.

The existing buffered `add`/`perform_blocking` path stays for non-proxy callers.

## Configuration and coherence

`Proxy::Impersonate->new(...)`:
- `impersonate => 'chrome131'` -- curl target applied to every upstream request
  (the coherence knob).
- `listen => '127.0.0.1:0'` -- bind address; port `0` = ephemeral; the daemon
  reports the actual `port`.
- `ca_dir => $path` -- persisted CA + `bundle.pem` (stable across runs, so
  WebKit trusts the CA once).
- `timeout`, `verify` (upstream, default on), `follow_redirects` (default off --
  the browser handles 3xx; the proxy forwards them).
- Reports `port` and `ca_bundle_path`.

Sub-project-3 coherence (preview, not built here): EV::WebKit's `fingerprint=>`
device profile maps to a curl target; sub-project 3 spawns the proxy with that
target, sets `SSL_CERT_FILE = ca_bundle_path`, and `set_proxy => 127.0.0.1:port`.
Sub-project 2 takes an explicit `impersonate` target.

## Error handling and connection lifecycle

- Upstream fails **before any response byte** (DNS/TLS/connect/timeout) ->
  `502 Bad Gateway` to WebKit. **After streaming started** -> abort the
  connection (close), so WebKit sees a truncated load (mirrors a real drop).
- WebKit-side TLS handshake failure -> log + close; malformed/oversized request
  head -> `400`.
- Keep-alive: the Connection state machine loops (parse -> forward+stream ->
  parse next) over one terminated TLS connection, honoring `Connection: close` /
  EOF; idle-timeout closes abandoned connections; per-request upstream timeout
  from config.
- Teardown: when WebKit closes, cancel any in-flight upstream
  (`curl_multi_remove_handle` + free), release the SSL/leaf, drop the io watcher.
- Backpressure: upstream->WebKit via `CURLPAUSE_RECV`; request bodies read fully
  before forwarding in v1.

## Testing

- **Task 1 = fail-fast spike (gates everything):** a tiny local Net::SSLeay
  HTTPS server presents a CA-signed leaf; EV::WebKit under xvfb loads it with
  `SSL_CERT_FILE=bundle`; assert no TLS error. Fail -> fall back to
  `set_tls_errors_policy(IGNORE)` (still proves the proxy path). This mirrors
  Curl::Impersonate's Task-1 gate: if WebKit will not trust the CA via
  `SSL_CERT_FILE`, decide the trust mechanism before building the proxy.
- **Unit (no network):** `HTTP.pm` (request-head parse, body framing, allow/drop
  lists, URL reconstruction on byte strings); `CA.pm` (mint a leaf, verify it
  chains to the CA, SAN present, bundle correct).
- **Integration (loopback, no external network):** proxy on `127.0.0.1:0`; a
  test client trusting our CA issues CONNECT to a local test origin (a tiny
  HTTPS server); assert the round-trip + incremental (chunked) streaming.
- **Live (`xt/`, CI_LIVE-gated):** fetch `https://tls.peet.ws/api/all` *through*
  the proxy with target chrome131 -> assert the origin-seen JA4 is Chrome's (the
  end-to-end fingerprint proof).
- **Valgrind** the integration test (Net::SSLeay + curl_multi; real perl binary,
  not the plenv shim).

## Key risks

1. **SSL_CERT_FILE trust (the linchpin).** WebKitGTK 6.0 exposes no custom-CA /
   GTlsDatabase setter (introspected: `WebKit::NetworkSession` has only
   `set_tls_errors_policy`, `allow_tls_certificate_for_host`,
   `set_proxy_settings`). `SSL_CERT_FILE` is the only no-root CA path;
   Task 1 proves it or we fall back to `IGNORE`.
2. **Streaming backpressure correctness.** The CURLPAUSE_RECV/CONT loop must not
   deadlock or drop data; covered by the integration streaming test + valgrind.
3. **Header-order coherence.** Getting the on-wire header profile Chrome-shaped
   while preserving request state; pinned by a test.
