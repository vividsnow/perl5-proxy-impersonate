# Proxy::Impersonate

An EV-based TLS-terminating MITM proxy that re-originates each request through
[`Curl::Impersonate`](../Curl-Impersonate), so origin servers see a chosen real
browser's **connection fingerprint** (TLS JA3/JA4 + HTTP/2 Akamai) instead of the
local TLS stack.

It is the companion proxy for [`EV::WebKit`](../EV-WebKit): WebKitGTK speaks
GnuTLS/libsoup and cannot present a browser's TLS fingerprint itself, so the
browser is pointed at this proxy, which terminates its TLS on localhost and
sends the request upstream with a real browser handshake via
`libcurl-impersonate`.

This is sub-project 2 of 3 in the network-fingerprint program (sub-project 1 is
`Curl::Impersonate`; sub-project 3 wires `EV::WebKit` through this proxy).

## Synopsis

```perl
use EV;
use Proxy::Impersonate;

my $proxy = Proxy::Impersonate->new(
    impersonate => 'chrome131',
    listen      => '127.0.0.1:0',
    cert_dir    => '/path/to/ca',
);
printf "proxy on 127.0.0.1:%d\n", $proxy->port;
$proxy->run;
```

A client (or EV::WebKit) uses it as an HTTP/HTTPS forward proxy. For HTTPS it
issues `CONNECT host:443`; the proxy terminates that TLS and re-originates the
request as the impersonated browser.

## Trust model

WebKitGTK 6.0 honors no custom-CA path (verified by a spike -- neither
`SSL_CERT_FILE` nor a settable `GTlsDatabase`), so the proxy presents a single
self-signed cert and the WebKit side accepts it:

```perl
$session->set_tls_errors_policy('ignore');
$browser->set_proxy("http://127.0.0.1:" . $proxy->port);
```

Safe because the WebKit-to-proxy hop is localhost and the proxy re-verifies the
real origin upstream (`verify => 1`, the default).

## Scope

HTTP + HTTPS-via-CONNECT, h1/h2 upstream, incremental streaming, keep-alive.
Out of scope in v1: WebSockets, HTTP/3, streaming request uploads.

## Requirements

- [`Curl::Impersonate`](../Curl-Impersonate) 0.02+ (streaming callbacks)
- `Net::SSLeay`, `EV`

## Install

```sh
perl Makefile.PL
make
make test                          # unit tests (no network)
PROXY_IT=1 make test               # + loopback integration
CI_LIVE=1 prove -l xt/             # + live JA4-through-proxy proof
make install
```

## License

Same terms as Perl itself.
