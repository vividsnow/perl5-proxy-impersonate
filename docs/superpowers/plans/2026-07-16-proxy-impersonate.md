# Proxy::Impersonate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone EV MITM proxy that terminates EV::WebKit's TLS and re-originates each request through `Curl::Impersonate`, so origins see a chosen browser's TLS/HTTP2 fingerprint.

**Architecture:** WebKit uses the daemon as an HTTP/HTTPS forward proxy. For HTTPS it sends `CONNECT`, and the proxy terminates the tunnelled TLS with a per-host leaf cert minted by a local root CA (trusted via `SSL_CERT_FILE`). The plaintext request is forwarded upstream via the EV-drivable `Curl::Impersonate::Multi`, and the response streams back. One EV loop drives the accept socket, per-connection Net::SSLeay io, and curl_multi's socket-action watchers.

**Tech Stack:** Perl 5.10+, EV, Net::SSLeay (TLS termination + cert minting), Curl::Impersonate (sub-project 1). Pure-Perl dist (no XS of its own).

> **Post-spike revision (2026-07-16):** Task 1 ran and FAILED -- WebKit honors neither `SSL_CERT_FILE` nor `SSL_CERT_DIR`. Trust falls back to `set_tls_errors_policy(IGNORE)` (set by sub-project 3). Under IGNORE, the CA/per-host-leaf/bundle design is dropped for a **single persisted self-signed cert**. This **supersedes Task 3**: instead of `CA.pm`, build `Proxy::Impersonate::Cert` -- generate/load ONE persisted self-signed cert+key (`cert.pem`/`key.pem` in `cert_dir`) and `apply_to_ctx($ctx)`; interface `new(cert_dir=>$p)`, `cert_path`, `key_path`, `apply_to_ctx`. It reuses the verified `gen_key`/`mk_cert` recipe from the spike (self-signed, SAN `DNS:localhost`). Task 5 loses the SNI callback (one cert on the CTX); Task 6 uses `cert_dir` (no `ca_bundle_path`). The CA-based Task 3 below is retained for history. Tasks 2, 4, 7, 8 are unaffected.

## Global Constraints

- Dist lives at `~/dev/perl-modules/Proxy-Impersonate` (git initialised; spec committed at `docs/superpowers/specs/2026-07-16-proxy-impersonate-design.md`).
- Commit author: `git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit`. No Co-Authored-By / LLM attribution.
- POD is plain ASCII; use `--` not em-dashes; no cross/x glyphs.
- Never use `sed`; edit with Perl one-liners or an editor.
- Use Net::SSLeay directly for both TLS termination and cert minting (no IO::Socket::SSL::Utils, no openssl CLI).
- MIN_PERL_VERSION 5.010. Dependencies: `EV`, `Net::SSLeay`, `Curl::Impersonate`.
- Scope v1: HTTP + HTTPS-via-CONNECT, HTTP/1.1 WebKit hop, h1/h2 upstream, incremental streaming, keep-alive. Deferred: WebSockets, HTTP/3, streaming request uploads, EC leaves, wildcard certs, bin/ CLI.
- Valgrind the integration test with the REAL perl binary (`$Config{perlpath}`), not the plenv shim.
- Response hashref shape from Curl::Impersonate (existing): `{status,headers,body}` on success, `{error,code}` on failure.

---

## Task 1: Fail-fast spike -- WebKit trusts a CA via SSL_CERT_FILE

This gates the whole design. It also exercises the Net::SSLeay CA+leaf recipe that `CA.pm` will formalise. If it fails, the fallback is `set_tls_errors_policy(IGNORE)`.

**Files:**
- Create: `xt/spike-ssl-cert-file.pl` (a standalone script, not a `t/` test)

**Interfaces:**
- Produces: empirical answer -- does WebKitGTK's network process validate a leaf whose CA is only in `SSL_CERT_FILE`? Recorded in the commit message.

- [ ] **Step 1: Write the spike script**

Create `xt/spike-ssl-cert-file.pl`:
```perl
use v5.10; use strict; use warnings;
use Net::SSLeay ();
use Socket;
use POSIX ':sys_wait_h';
use File::Temp qw(tempdir);

Net::SSLeay::initialize();
my $dir = tempdir(CLEANUP => 1);

# --- mint a CA and a leaf for 127.0.0.1 (raw Net::SSLeay recipe) ---
sub gen_key { my $rsa = Net::SSLeay::RSA_generate_key(2048, 0x10001);
    my $pk = Net::SSLeay::EVP_PKEY_new(); Net::SSLeay::EVP_PKEY_assign_RSA($pk, $rsa); $pk }
sub mk_cert {
    my (%a) = @_;                       # cn, pkey, issuer_cert, issuer_key, ca=>bool, san
    my $x = Net::SSLeay::X509_new();
    Net::SSLeay::X509_set_version($x, 2);
    Net::SSLeay::ASN1_INTEGER_set(Net::SSLeay::X509_get_serialNumber($x), $a{serial} // int(rand(2**31)));
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notBefore($x), 0);
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notAfter($x), 60*60*24*825);
    Net::SSLeay::X509_set_pubkey($x, $a{pkey});
    my $nm = Net::SSLeay::X509_get_subject_name($x);
    Net::SSLeay::X509_NAME_add_entry_by_txt($nm, 'CN', &Net::SSLeay::MBSTRING_UTF8, $a{cn}, -1, 0, 0);
    my $icert = $a{issuer_cert} // $x;   # self-signed if no issuer
    Net::SSLeay::X509_set_issuer_name($x, Net::SSLeay::X509_get_subject_name($icert));
    if ($a{ca}) {
        Net::SSLeay::P_X509_add_extensions($x, $icert,
            &Net::SSLeay::NID_basic_constraints => 'critical,CA:TRUE',
            &Net::SSLeay::NID_key_usage         => 'critical,keyCertSign,cRLSign');
    } else {
        Net::SSLeay::P_X509_add_extensions($x, $icert,
            &Net::SSLeay::NID_basic_constraints => 'CA:FALSE',
            &Net::SSLeay::NID_subject_alt_name  => "DNS:$a{san}",
            &Net::SSLeay::NID_key_usage         => 'digitalSignature,keyEncipherment',
            &Net::SSLeay::NID_ext_key_usage     => 'serverAuth');
    }
    Net::SSLeay::X509_sign($x, $a{issuer_key} // $a{pkey}, Net::SSLeay::EVP_sha256());
    $x;
}
my $ca_key  = gen_key();
my $ca_cert = mk_cert(cn => 'Proxy::Impersonate spike CA', pkey => $ca_key, ca => 1);
my $lf_key  = gen_key();
my $lf_cert = mk_cert(cn => '127.0.0.1', pkey => $lf_key,
                      issuer_cert => $ca_cert, issuer_key => $ca_key, san => '127.0.0.1');

my $ca_pem   = Net::SSLeay::PEM_get_string_X509($ca_cert);
my $lf_pem   = Net::SSLeay::PEM_get_string_X509($lf_cert);
my $lf_kpem  = Net::SSLeay::PEM_get_string_PrivateKey($lf_key);
# bundle = system CAs + our CA (system path best-effort)
my ($sys) = grep { -r } qw(/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt);
my $bundle = "$dir/bundle.pem";
open my $bh, '>', $bundle or die $!;
if ($sys) { open my $s, '<', $sys; local $/; print $bh <$s>; close $s }
print $bh $ca_pem; close $bh;
my ($cf, $kf) = ("$dir/leaf.crt", "$dir/leaf.key");
open my $c, '>', $cf; print $c $lf_pem; close $c;
open my $k, '>', $kf; print $k $lf_kpem; close $k;

# --- tiny blocking HTTPS server on 127.0.0.1:0 presenting the leaf ---
socket(my $srv, PF_INET, SOCK_STREAM, 0) or die $!;
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in(0, inet_aton('127.0.0.1'))) or die $!;
listen($srv, 5) or die $!;
my $port = (sockaddr_in(getsockname($srv)))[0];

my $pid = fork // die $!;
if ($pid == 0) {                        # server child
    my $ctx = Net::SSLeay::CTX_new();
    Net::SSLeay::set_cert_and_key($ctx, $cf, $kf);
    accept(my $cli, $srv) or exit 1;
    my $ssl = Net::SSLeay::new($ctx);
    Net::SSLeay::set_fd($ssl, fileno($cli));
    Net::SSLeay::accept($ssl);
    Net::SSLeay::read($ssl);            # request
    Net::SSLeay::write($ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    Net::SSLeay::free($ssl); close $cli; exit 0;
}
close $srv;

# --- point EV::WebKit at it via SSL_CERT_FILE and load the page ---
$ENV{SSL_CERT_FILE} = $bundle;
$ENV{SSL_CERT_DIR}  = '';               # force the file path only
my $rc = system($^X, '-e', <<"WK", $port);
use EV; use EV::WebKit;
my \$ok = 0; my \$tls_err = 0;
my \$b = EV::WebKit->new(on_load_changed => sub {
    my (\$self, \$ev) = \@_;
    if (\$ev eq 'finished') { \$ok = 1; EV::break }
}, on_load_failed => sub { \$tls_err = 1; EV::break });
\$b->load_uri("https://127.0.0.1:\$ARGV[0]/");
my \$t = EV::timer(30, 0, sub { EV::break });
EV::run;
exit(\$ok && !\$tls_err ? 0 : 3);
WK
waitpid($pid, 0);
say $rc == 0 ? "SPIKE PASS: WebKit trusted the CA via SSL_CERT_FILE"
             : "SPIKE FAIL (rc=$rc): fall back to set_tls_errors_policy(IGNORE)";
exit($rc == 0 ? 0 : 1);
```

- [ ] **Step 2: Run the spike under xvfb**

Run: `cd ~/dev/perl-modules/Proxy-Impersonate && xvfb-run -a perl -I../EV-WebKit/lib xt/spike-ssl-cert-file.pl`
Expected: `SPIKE PASS: WebKit trusted the CA via SSL_CERT_FILE`.

Note: the exact EV::WebKit constructor/callback names (`on_load_changed`, `on_load_failed`, `load_uri`) must be matched to the real API -- check `~/dev/perl-modules/EV-WebKit/lib/EV/WebKit.pm` and adjust before running. If PASS, `SSL_CERT_FILE` is the trust mechanism. If FAIL, record it and switch `CA.pm`'s consumer to call `WebKit::NetworkSession::set_tls_errors_policy($session, 'ignore')` instead (design's documented fallback); the rest of the plan is unchanged except the trust wiring.

- [ ] **Step 3: Commit the spike + its verdict**

```bash
git add xt/spike-ssl-cert-file.pl
git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit -m "spike: WebKit trusts a Net::SSLeay CA via SSL_CERT_FILE (<PASS|FAIL: verdict>)"
```

---

## Task 2: Curl::Impersonate::Multi streaming callbacks (prerequisite, sub-project 1 dist)

The proxy needs incremental upstream delivery with backpressure. Extend `Curl::Impersonate::Multi` in `~/dev/perl-modules/Curl-Impersonate` (its own repo). The existing buffered `add`/`perform_blocking` stays.

**Files:**
- Modify: `~/dev/perl-modules/Curl-Impersonate/Impersonate.xs`
- Modify: `~/dev/perl-modules/Curl-Impersonate/lib/Curl/Impersonate.pm` (VERSION bump 0.01 -> 0.02, POD)
- Test: `~/dev/perl-modules/Curl-Impersonate/t/50-streaming.t`

**Interfaces:**
- Produces:
  - `$multi->add_streaming($handle, \%req, { on_headers => sub {($status,$headers)}, on_body => sub {($chunk) -> truthy pauses}, on_done => sub {($err)} })`
  - `$multi->resume($handle)` -- unpause a paused transfer and nudge the loop.
- Consumes: the existing `ci_req`/`ci_multi` structs and `drain_done` (Task 6 of the Curl::Impersonate plan).

- [ ] **Step 1: Write the failing test**

Create `t/50-streaming.t`:
```perl
use v5.10; use strict; use warnings;
use Test::More;
use Curl::Impersonate;
plan skip_all => 'set CI_LIVE=1' unless $ENV{CI_LIVE};

my $m = Curl::Impersonate->multi;
my ($status, $hdrs, $body, $done, $err);
my $h = Curl::Impersonate->new(impersonate => 'chrome131', timeout => 20);
$m->add_streaming($h, { url => 'https://tls.peet.ws/api/clean' }, {
    on_headers => sub { ($status, $hdrs) = @_ },
    on_body    => sub { $body .= $_[0]; return 0 },   # never pause
    on_done    => sub { ($err) = @_; $done = 1 },
});
$m->perform_blocking;
is($status, 200, 'on_headers got status 200');
ok($hdrs && ref $hdrs eq 'HASH', 'on_headers got a headers hashref');
ok(length($body) > 10, 'on_body accumulated a body');
ok($done && !$err, 'on_done fired with no error');
like($body, qr/ja3|tls/i, 'streamed body is the fingerprint JSON');
done_testing;
```

- [ ] **Step 2: Run (RED)**

Run: `cd ~/dev/perl-modules/Curl-Impersonate && CI_LIVE=1 prove -b t/50-streaming.t`
Expected: FAIL (`add_streaming` undefined).

- [ ] **Step 3: Extend the ci_req struct + streaming callbacks in XS**

In `Impersonate.xs`, add streaming fields to `ci_req` (after `HV *headers;`):
```c
    SV *on_headers;   /* streaming: fired once with (status, headers) */
    SV *on_body;      /* streaming: fired per chunk; truthy return pauses */
    int streaming;    /* 1 = streaming mode (cb is on_done) */
    int headers_sent; /* 1 = on_headers already fired */
```

Replace `body_cb` so it streams when the write target is a `ci_req` in streaming mode. The cleanest wiring: in streaming mode set `CURLOPT_WRITEDATA` to the `ci_req*` itself (not `&r->body`) and branch in `body_cb`:
```c
static size_t body_cb(char *p, size_t s, size_t n, void *u){
    dTHX;
    ci_req *r = (ci_req *) u;              /* streaming path passes the ci_req */
    size_t len = s * n;
    if (!r->streaming) {                   /* buffered path: u is &r->body */
        struct buf *b = (struct buf *) u;
        Renew(b->data, b->len + len + 1, char);
        memcpy(b->data + b->len, p, len); b->len += len; b->data[b->len] = 0;
        return len;
    }
    if (!r->headers_sent) {                /* fire on_headers once */
        long code = 0; curl_easy_getinfo(r->easy, CURLINFO_RESPONSE_CODE, &code);
        dSP; ENTER; SAVETMPS; PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSViv(code)));
        XPUSHs(sv_2mortal(newRV_inc((SV*) r->headers)));
        PUTBACK; call_sv(r->on_headers, G_VOID|G_DISCARD|G_EVAL);
        FREETMPS; LEAVE; r->headers_sent = 1;
    }
    {                                       /* fire on_body($chunk); truthy = pause */
        int pause = 0; dSP; ENTER; SAVETMPS; PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSVpvn(p, len)));
        PUTBACK;
        int cnt = call_sv(r->on_body, G_SCALAR|G_EVAL);
        SPAGAIN;
        if (cnt) { SV *rv = POPs; pause = SvTRUE(rv); }
        PUTBACK; FREETMPS; LEAVE;
        if (pause) return CURL_WRITEFUNC_PAUSE;
    }
    return len;
}
```
Note: buffered `apply_request` keeps `CURLOPT_WRITEDATA = &body`; streaming sets `CURLOPT_WRITEDATA = r`. Guard the buffered branch with `r->streaming` -- but the buffered path passes `&r->body`, a different pointer, so the two are distinguished by which `add` set WRITEDATA. To keep it unambiguous, ALWAYS pass the `ci_req*` as WRITEDATA and branch on `r->streaming`; update the buffered `apply_request` call sites to set `CURLOPT_WRITEDATA, r` and have the buffered branch use `&r->body`.

- [ ] **Step 4: add_streaming XSUB**

Add to `PACKAGE = Curl::Impersonate::Multi`:
```c
void
add_streaming(self_sv, easy_sv, req_hv, cbs_hv)
    SV *self_sv
    SV *easy_sv
    SV *req_hv
    SV *cbs_hv
  PREINIT:
    ci_multi *m; ci_t *ci; HV *req; HV *cbs; SV **sv; ci_req *r;
    const char *method; const char *url; SV *body_sv; SV *hdrs;
  CODE:
    m  = (ci_multi *) SvIV((SV *) SvRV(self_sv));
    ci = (ci_t *) SvIV((SV *) SvRV(easy_sv));
    req = (HV *) SvRV(req_hv); cbs = (HV *) SvRV(cbs_hv);
    method  = (sv = hv_fetchs(req, "method", 0))  && SvOK(*sv) ? SvPV_nolen(*sv) : "GET";
    url     = (sv = hv_fetchs(req, "url", 0))     && SvOK(*sv) ? SvPV_nolen(*sv) : NULL;
    body_sv = (sv = hv_fetchs(req, "body", 0))    ? *sv : &PL_sv_undef;
    hdrs    = (sv = hv_fetchs(req, "headers", 0)) ? *sv : &PL_sv_undef;
    if (!url) croak("add_streaming: url is required");
    Newxz(r, 1, ci_req);
    r->easy = ci->easy; r->owner = newSVsv(easy_sv); r->headers = newHV();
    r->streaming = 1;
    r->on_headers = (sv = hv_fetchs(cbs, "on_headers", 0)) ? newSVsv(*sv) : &PL_sv_undef;
    r->on_body    = (sv = hv_fetchs(cbs, "on_body", 0))    ? newSVsv(*sv) : &PL_sv_undef;
    r->cb         = (sv = hv_fetchs(cbs, "on_done", 0))    ? newSVsv(*sv) : newSV(0);  /* reuse cb as on_done */
    r->hlist = apply_request(ci->easy, method, url, hdrs, body_sv, &r->body, r->headers);
    curl_easy_setopt(ci->easy, CURLOPT_PRIVATE, r);
    curl_multi_add_handle(m->multi, ci->easy);
```
In `dispatch_done`, when `r->streaming`, do NOT build a response hash -- just call `r->cb` (on_done) with `($err_or_undef)` and free the extra SVs:
```c
    if (r->streaming) {
        SV *err = (result != CURLE_OK) ? sv_2mortal(newSVpv(curl_easy_strerror(result),0)) : &PL_sv_undef;
        dSP; ENTER; SAVETMPS; PUSHMARK(SP); XPUSHs(err); PUTBACK;
        call_sv(r->cb, G_VOID|G_DISCARD|G_EVAL); FREETMPS; LEAVE;
    } else { /* existing buffered ($res,$err) path */ }
    /* cleanup: also SvREFCNT_dec(r->on_headers), SvREFCNT_dec(r->on_body) when streaming */
```

- [ ] **Step 5: resume XSUB**

```c
void
resume(self_sv, easy_sv)
    SV *self_sv
    SV *easy_sv
  PREINIT:
    ci_multi *m; ci_t *ci; int still;
  CODE:
    m  = (ci_multi *) SvIV((SV *) SvRV(self_sv));
    ci = (ci_t *) SvIV((SV *) SvRV(easy_sv));
    curl_easy_pause(ci->easy, CURLPAUSE_CONT);
    curl_multi_socket_action(m->multi, CURL_SOCKET_TIMEOUT, 0, &still);  /* nudge delivery */
    drain_done(m);

void
remove(self_sv, easy_sv)
    SV *self_sv
    SV *easy_sv
  PREINIT:
    ci_multi *m; ci_t *ci; ci_req *r;
  CODE:
    m  = (ci_multi *) SvIV((SV *) SvRV(self_sv));
    ci = (ci_t *) SvIV((SV *) SvRV(easy_sv));
    r = NULL; curl_easy_getinfo(ci->easy, CURLINFO_PRIVATE, &r);
    curl_easy_setopt(ci->easy, CURLOPT_PRIVATE, NULL);
    curl_multi_remove_handle(m->multi, ci->easy);
    if (r) {                             /* cancel: free the req without firing on_done */
        if (r->hlist) curl_slist_free_all(r->hlist);
        Safefree(r->body.data);
        SvREFCNT_dec((SV *) r->headers);
        SvREFCNT_dec(r->cb); SvREFCNT_dec(r->owner);
        if (r->streaming) { SvREFCNT_dec(r->on_headers); SvREFCNT_dec(r->on_body); }
        Safefree(r);
    }
```
(`remove($handle)` cancels an in-flight transfer -- used by Connection teardown when WebKit closes mid-response.)

- [ ] **Step 6: Perl wrappers + VERSION bump + build + test (GREEN)**

In `lib/Curl/Impersonate.pm` bump `our $VERSION = '0.02';`. The `add_streaming`/`resume` are XS methods on `Curl::Impersonate::Multi` (no Perl wrapper needed).
Run: `cd ~/dev/perl-modules/Curl-Impersonate && perl Makefile.PL && make && CI_LIVE=1 prove -b t/50-streaming.t`
Expected: PASS (5 tests).

- [ ] **Step 7: Reinstall the updated Curl::Impersonate**

Run: `make install` (so the Proxy dist consumes 0.02).

- [ ] **Step 8: Commit**

```bash
git add Impersonate.xs lib/Curl/Impersonate.pm t/50-streaming.t
git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit -m "Curl::Impersonate: streaming callbacks (on_headers/on_body/resume/on_done + CURLPAUSE)"
```

---

## Task 3: Proxy::Impersonate::CA -- root CA, per-host leaf, bundle

First Proxy module; creates the dist scaffolding (Makefile.PL, lib tree).

**Files:**
- Create: `~/dev/perl-modules/Proxy-Impersonate/Makefile.PL`
- Create: `lib/Proxy/Impersonate/CA.pm`
- Test: `t/10-ca.t`

**Interfaces:**
- Produces:
  - `Proxy::Impersonate::CA->new(ca_dir => $path)` -- loads or generates `ca.crt`/`ca.key`, writes `bundle.pem`.
  - `$ca->ca_bundle_path` -> path string.
  - `$ca->leaf_for($host)` -> `($cert_obj, $key_obj)` Net::SSLeay X509/EVP_PKEY, cached by host.
  - `$ca->apply_to_ctx($ssl_ctx, $host)` -- set the leaf cert+key on a Net::SSLeay SSL_CTX for `$host`.

- [ ] **Step 1: Scaffold Makefile.PL**

Create `Makefile.PL`:
```perl
use v5.10; use strict; use warnings;
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME             => 'Proxy::Impersonate',
    VERSION_FROM     => 'lib/Proxy/Impersonate.pm',
    ABSTRACT         => 'EV MITM proxy that re-originates with a browser TLS/HTTP2 fingerprint',
    AUTHOR           => 'vividsnow',
    LICENSE          => 'perl_5',
    MIN_PERL_VERSION => '5.010',
    PREREQ_PM        => { 'EV' => 0, 'Net::SSLeay' => '1.85', 'Curl::Impersonate' => '0.02' },
    TEST_REQUIRES    => { 'Test::More' => 0 },
);
```
(`lib/Proxy/Impersonate.pm` with `$VERSION` is created in Task 6; add a stub `our $VERSION='0.01';` now so VERSION_FROM works -- see Step 2.)

- [ ] **Step 2: Stub the main module for VERSION_FROM**

Create `lib/Proxy/Impersonate.pm` with just:
```perl
package Proxy::Impersonate;
use v5.10; use strict; use warnings;
our $VERSION = '0.01';
1;
```

- [ ] **Step 3: Write the failing test**

Create `t/10-ca.t`:
```perl
use v5.10; use strict; use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Net::SSLeay ();
use Proxy::Impersonate::CA;

my $dir = tempdir(CLEANUP => 1);
my $ca  = Proxy::Impersonate::CA->new(ca_dir => $dir);
ok(-r "$dir/ca.crt" && -r "$dir/ca.key", 'CA cert+key persisted');
ok(-r $ca->ca_bundle_path, 'bundle written');

# bundle contains our CA
open my $b, '<', $ca->ca_bundle_path; local $/; my $bundle = <$b>; close $b;
open my $c, '<', "$dir/ca.crt"; my $cacrt = <$c>; close $c;
like($bundle, qr/\QBEGIN CERTIFICATE\E/, 'bundle has PEM certs');
ok(index($bundle, (split /\n/, $cacrt)[1]) >= 0, 'bundle includes our CA body');

# leaf chains to the CA and carries the SAN
my ($cert, $key) = $ca->leaf_for('example.com');
ok($cert && $key, 'leaf_for returns cert+key');
my $store = Net::SSLeay::X509_STORE_new();
my $cafh  = Net::SSLeay::X509_STORE_add_cert($store,
    Net::SSLeay::d2i_X509(undef)) if 0;   # (chain check below via verify)
# Reload the CA cert object and verify the leaf's issuer == CA subject:
is(Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_issuer_name($cert)),
   Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($ca->ca_cert)),
   'leaf issuer == CA subject');
my $san = Net::SSLeay::X509_get_subjectAltNames($cert);
ok((grep { $_ eq 'example.com' } map { $_->[1] } @$san), 'leaf SAN has the host') if $san;

# caching: same object back for the same host
my ($cert2) = $ca->leaf_for('example.com');
is($cert2, $cert, 'leaf is cached per host');
done_testing;
```

- [ ] **Step 4: Run (RED)**

Run: `cd ~/dev/perl-modules/Proxy-Impersonate && perl Makefile.PL && prove -l t/10-ca.t`
Expected: FAIL (`Proxy::Impersonate::CA` not found).

- [ ] **Step 5: Implement CA.pm**

Create `lib/Proxy/Impersonate/CA.pm`:
```perl
package Proxy::Impersonate::CA;
use v5.10; use strict; use warnings;
use Carp ();
use Net::SSLeay ();

BEGIN { Net::SSLeay::initialize() }

sub new {
    my ($class, %o) = @_;
    my $dir = $o{ca_dir} or Carp::croak('CA: ca_dir required');
    -d $dir or mkdir $dir or Carp::croak("CA: mkdir $dir: $!");
    my $self = bless { dir => $dir, leaves => {} }, $class;
    $self->_load_or_generate_ca;
    $self->_write_bundle;
    return $self;
}

sub ca_cert        { $_[0]{ca_cert} }
sub ca_bundle_path { $_[0]{bundle} }

sub _gen_key {
    my $rsa = Net::SSLeay::RSA_generate_key(2048, 0x10001);
    my $pk  = Net::SSLeay::EVP_PKEY_new();
    Net::SSLeay::EVP_PKEY_assign_RSA($pk, $rsa);
    return $pk;
}

sub _mk_cert {
    my (%a) = @_;   # cn, pkey, issuer_cert, issuer_key, ca, san, serial
    my $x = Net::SSLeay::X509_new();
    Net::SSLeay::X509_set_version($x, 2);
    Net::SSLeay::ASN1_INTEGER_set(Net::SSLeay::X509_get_serialNumber($x),
        $a{serial} // (int(rand(2**31)) | 1));
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notBefore($x), -3600);
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notAfter($x), 60*60*24*825);
    Net::SSLeay::X509_set_pubkey($x, $a{pkey});
    my $nm = Net::SSLeay::X509_get_subject_name($x);
    Net::SSLeay::X509_NAME_add_entry_by_txt($nm, 'CN', &Net::SSLeay::MBSTRING_UTF8, $a{cn}, -1, 0, 0);
    my $icert = $a{issuer_cert} // $x;
    Net::SSLeay::X509_set_issuer_name($x, Net::SSLeay::X509_get_subject_name($icert));
    if ($a{ca}) {
        Net::SSLeay::P_X509_add_extensions($x, $icert,
            &Net::SSLeay::NID_basic_constraints => 'critical,CA:TRUE',
            &Net::SSLeay::NID_key_usage         => 'critical,keyCertSign,cRLSign');
    } else {
        Net::SSLeay::P_X509_add_extensions($x, $icert,
            &Net::SSLeay::NID_basic_constraints => 'CA:FALSE',
            &Net::SSLeay::NID_subject_alt_name  => "DNS:$a{san}",
            &Net::SSLeay::NID_key_usage         => 'digitalSignature,keyEncipherment',
            &Net::SSLeay::NID_ext_key_usage     => 'serverAuth');
    }
    Net::SSLeay::X509_sign($x, $a{issuer_key} // $a{pkey}, Net::SSLeay::EVP_sha256());
    return $x;
}

sub _load_or_generate_ca {
    my ($self) = @_;
    my ($cf, $kf) = ("$self->{dir}/ca.crt", "$self->{dir}/ca.key");
    if (-r $cf && -r $kf) {
        my $bio_c = Net::SSLeay::BIO_new_file($cf, 'r');
        $self->{ca_cert} = Net::SSLeay::PEM_read_bio_X509($bio_c);
        Net::SSLeay::BIO_free($bio_c);
        my $bio_k = Net::SSLeay::BIO_new_file($kf, 'r');
        $self->{ca_key} = Net::SSLeay::PEM_read_bio_PrivateKey($bio_k);
        Net::SSLeay::BIO_free($bio_k);
        return;
    }
    my $key  = _gen_key();
    my $cert = _mk_cert(cn => 'Proxy::Impersonate CA', pkey => $key, ca => 1);
    $self->{ca_key} = $key; $self->{ca_cert} = $cert;
    _spew($cf, Net::SSLeay::PEM_get_string_X509($cert), 0644);
    _spew($kf, Net::SSLeay::PEM_get_string_PrivateKey($key), 0600);
}

sub _write_bundle {
    my ($self) = @_;
    my $bundle = "$self->{dir}/bundle.pem";
    my ($sys) = grep { -r } (
        ($ENV{SSL_CERT_FILE} // ()),
        '/etc/ssl/certs/ca-certificates.crt',
        '/etc/pki/tls/certs/ca-bundle.crt',
    );
    my $out = '';
    if ($sys) { open my $s, '<', $sys or Carp::carp("CA: read $sys: $!");
                if ($s) { local $/; $out = <$s>; close $s } }
    else { Carp::carp('CA: no system CA bundle found; bundle has only our CA') }
    $out .= Net::SSLeay::PEM_get_string_X509($self->{ca_cert});
    _spew($bundle, $out, 0644);
    $self->{bundle} = $bundle;
}

sub leaf_for {
    my ($self, $host) = @_;
    return @{ $self->{leaves}{$host} } if $self->{leaves}{$host};
    my $key  = _gen_key();
    my $cert = _mk_cert(cn => $host, pkey => $key, san => $host,
                        issuer_cert => $self->{ca_cert}, issuer_key => $self->{ca_key});
    $self->{leaves}{$host} = [$cert, $key];
    return ($cert, $key);
}

sub apply_to_ctx {
    my ($self, $ctx, $host) = @_;
    my ($cert, $key) = $self->leaf_for($host);
    Net::SSLeay::CTX_use_certificate($ctx, $cert);
    Net::SSLeay::CTX_use_PrivateKey($ctx, $key);
}

sub _spew {
    my ($path, $data, $mode) = @_;
    open my $fh, '>', $path or Carp::croak("CA: write $path: $!");
    print $fh $data; close $fh;
    chmod $mode, $path if defined $mode;
}

1;
```

- [ ] **Step 6: Run (GREEN)**

Run: `prove -l t/10-ca.t`
Expected: PASS. If a Net::SSLeay helper name differs on the installed version (e.g. `X509_get_subjectAltNames`, `P_X509_add_extensions`), adjust to the installed API (`perldoc Net::SSLeay` / grep its `.pm`) -- these are the known version-sensitive calls.

- [ ] **Step 7: Commit**

```bash
git add Makefile.PL lib/Proxy/Impersonate.pm lib/Proxy/Impersonate/CA.pm t/10-ca.t
git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit -m "Proxy::Impersonate::CA: root CA + per-host leaf minting + bundle (Net::SSLeay)"
```

---

## Task 4: Proxy::Impersonate::HTTP -- request/response head codec

Pure functions, no sockets.

**Files:**
- Create: `lib/Proxy/Impersonate/HTTP.pm`
- Test: `t/20-http.t`

**Interfaces:**
- Produces:
  - `Proxy::Impersonate::HTTP::parse_request_head($bytes)` -> `undef` (incomplete) or `{ method, target, version, headers => \@pairs, header_end => $offset }`. `\@pairs` preserves order and case as received.
  - `Proxy::Impersonate::HTTP::body_length(\@pairs)` -> `($mode, $n)` where `$mode` is `'length'` (with `$n`), `'chunked'`, or `'none'`.
  - `Proxy::Impersonate::HTTP::coherent_headers(\@pairs)` -> `\%forward` -- lower-cased, keeping only Cookie/Referer/Origin/Content-Type/Authorization (the allowlist), dropping the rest.
  - `Proxy::Impersonate::HTTP::response_head($status, \%headers)` -> bytes for the status line + headers + CRLF.

- [ ] **Step 1: Write the failing test**

Create `t/20-http.t`:
```perl
use v5.10; use strict; use warnings;
use Test::More;
use Proxy::Impersonate::HTTP qw(parse_request_head body_length coherent_headers response_head);

# incomplete head -> undef
is(parse_request_head("GET / HTTP/1.1\r\nHost: x"), undef, 'incomplete head is undef');

my $raw = "POST /p?q=1 HTTP/1.1\r\nHost: ex.com\r\nContent-Length: 5\r\n"
        . "Cookie: a=b\r\nUser-Agent: WebKit\r\n\r\nhello";
my $r = parse_request_head($raw);
is($r->{method}, 'POST', 'method');
is($r->{target}, '/p?q=1', 'target');
is($r->{version}, 'HTTP/1.1', 'version');
is(substr($raw, $r->{header_end}), 'hello', 'header_end points at body');

my ($mode, $n) = body_length($r->{headers});
is($mode, 'length', 'content-length mode'); is($n, 5, 'length 5');

my $fwd = coherent_headers($r->{headers});
is($fwd->{cookie}, 'a=b', 'cookie kept');
ok(!exists $fwd->{'user-agent'}, 'user-agent dropped (Chrome template wins)');

my $head = response_head(200, { 'content-type' => 'text/html' });
like($head, qr!\AHTTP/1\.1 200 [^\r]*\r\n!, 'status line');
like($head, qr/content-type: text\/html\r\n/, 'header line');
like($head, qr/\r\n\r\n\z/, 'ends with blank line');
done_testing;
```

- [ ] **Step 2: Run (RED)**

Run: `prove -l t/20-http.t` -- Expected: FAIL (module missing).

- [ ] **Step 3: Implement HTTP.pm**

Create `lib/Proxy/Impersonate/HTTP.pm`:
```perl
package Proxy::Impersonate::HTTP;
use v5.10; use strict; use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(parse_request_head body_length coherent_headers response_head);

my %REASON = (200=>'OK',301=>'Moved Permanently',302=>'Found',400=>'Bad Request',
    404=>'Not Found',500=>'Internal Server Error',502=>'Bad Gateway',504=>'Gateway Timeout');

# keep only per-request state; the impersonate template supplies the rest
my %FORWARD = map { $_ => 1 } qw(cookie referer origin content-type authorization);

sub parse_request_head {
    my ($buf) = @_;
    my $end = index($buf, "\r\n\r\n");
    return undef if $end < 0;
    my $head = substr($buf, 0, $end);
    my ($line, @lines) = split /\r\n/, $head;
    my ($method, $target, $version) = $line =~ m{^(\S+)\s+(\S+)\s+(HTTP/\d\.\d)$}
        or return undef;
    my @pairs;
    for my $h (@lines) {
        my ($k, $v) = $h =~ /^([^:]+):[ \t]*(.*?)[ \t]*$/ or next;
        push @pairs, [$k, $v];
    }
    return { method => $method, target => $target, version => $version,
             headers => \@pairs, header_end => $end + 4 };
}

sub _get { my ($pairs, $name) = @_; $name = lc $name;
    for (@$pairs) { return $_->[1] if lc($_->[0]) eq $name } return undef }

sub body_length {
    my ($pairs) = @_;
    my $te = _get($pairs, 'transfer-encoding');
    return ('chunked') if $te && $te =~ /chunked/i;
    my $cl = _get($pairs, 'content-length');
    return ('length', $cl + 0) if defined $cl && $cl =~ /^\d+$/;
    return ('none');
}

sub coherent_headers {
    my ($pairs) = @_;
    my %out;
    for (@$pairs) { my $k = lc $_->[0]; $out{$k} = $_->[1] if $FORWARD{$k} }
    return \%out;
}

sub response_head {
    my ($status, $headers) = @_;
    my $reason = $REASON{$status} // 'Status';
    my $out = "HTTP/1.1 $status $reason\r\n";
    $out .= "$_: $headers->{$_}\r\n" for sort keys %$headers;
    $out .= "\r\n";
    return $out;
}

1;
```

- [ ] **Step 4: Run (GREEN)** -- `prove -l t/20-http.t` -- Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/Proxy/Impersonate/HTTP.pm t/20-http.t
git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit -m "Proxy::Impersonate::HTTP: request-head parse + body framing + coherent headers + response head"
```

---

## Task 5: Proxy::Impersonate::Connection -- per-connection state machine

The largest unit. Terminates TLS, parses requests, forwards via the shared Multi streaming, writes responses back, keep-alive, teardown.

**Files:**
- Create: `lib/Proxy/Impersonate/Connection.pm`
- Test: `t/30-connection.t` (unit-level: CONNECT handling + request-to-upstream mapping against a fake Multi + a socketpair)

**Interfaces:**
- Consumes: `Proxy::Impersonate::CA` (`apply_to_ctx`, `leaf_for`), `Proxy::Impersonate::HTTP` (parse/body/headers/response_head), a `Curl::Impersonate::Multi` (`add_streaming`, `resume`), a `Curl::Impersonate` handle factory `sub { Curl::Impersonate->new(impersonate=>$target, verify=>1, timeout=>$t) }`.
- Produces: `Proxy::Impersonate::Connection->new(fd => $sock, ca => $ca, multi => $m, make_handle => $cb, on_close => $cb)` and `$conn->start` (arms EV io). Internally state-drives; no other public API.

- [ ] **Step 1: Write the failing test (CONNECT + plaintext parse over a socketpair)**

Create `t/30-connection.t`:
```perl
use v5.10; use strict; use warnings;
use Test::More;
use Socket;
use Proxy::Impersonate::Connection;

# Fake Multi captures add_streaming calls and lets us drive callbacks.
package FakeMulti;
sub new { bless { calls => [] }, shift }
sub add_streaming { my ($s,$h,$req,$cbs)=@_; push @{$s->{calls}}, [$req,$cbs] }
sub resume {}
package main;

# A CONNECT request should get a 200 and flip the connection to TLS mode.
socketpair(my $a, my $b, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die $!;
my $fm = FakeMulti->new;
my $conn = Proxy::Impersonate::Connection->new(
    fd => $b, ca => undef, multi => $fm,
    make_handle => sub { bless {}, 'FakeHandle' }, on_close => sub {},
);
# feed a CONNECT and check the proxy's 200 reply (test the parser/reply directly)
my $reply = $conn->_handle_line("CONNECT ex.com:443 HTTP/1.1\r\nHost: ex.com:443\r\n\r\n");
like($reply, qr!\AHTTP/1\.1 200!, 'CONNECT gets 200 Connection established');
is($conn->{mode}, 'tls', 'connection switched to tls mode');
is($conn->{connect_host}, 'ex.com', 'CONNECT host captured');
done_testing;
```
(Testing the TLS data path end-to-end lives in Task 6's integration test; here we unit-test the CONNECT reply + state transition + host capture via the internal `_handle_line` seam.)

- [ ] **Step 2: Run (RED)** -- `prove -l t/30-connection.t` -- Expected: FAIL.

- [ ] **Step 3: Implement Connection.pm**

Create `lib/Proxy/Impersonate/Connection.pm`. The state machine (abbreviated to the load-bearing structure -- implement each method fully):
```perl
package Proxy::Impersonate::Connection;
use v5.10; use strict; use warnings;
use EV;
use Net::SSLeay ();
use Proxy::Impersonate::HTTP qw(parse_request_head body_length coherent_headers response_head);

sub new {
    my ($class, %o) = @_;
    my $self = bless {
        sock => $o{fd}, ca => $o{ca}, multi => $o{multi},
        make_handle => $o{make_handle}, on_close => $o{on_close} // sub {},
        target => $o{target},
        mode => 'plain',            # 'plain' -> raw h1; 'tls' after CONNECT
        rbuf => '', wbuf => '',
        connect_host => undef, ssl => undef, ctx => undef,
    }, $class;
    return $self;
}

sub start {
    my ($self) = @_;
    my $fd = fileno($self->{sock});
    $self->{sock}->blocking(0);
    $self->{rw} = EV::io($fd, EV::READ, sub { $self->_readable });
    return $self;
}

# --- plaintext line handling (also the test seam) ---
sub _handle_line {
    my ($self, $head) = @_;
    my $r = parse_request_head($head) or return undef;
    if ($r->{method} eq 'CONNECT') {
        ($self->{connect_host}) = $r->{target} =~ /^([^:]+)/;
        $self->{mode} = 'tls';
        return "HTTP/1.1 200 Connection established\r\n\r\n";
    }
    # plain HTTP absolute-form: forward directly
    $self->_forward($r, absolute => 1);
    return undef;
}

# --- readable dispatch: plain vs post-CONNECT TLS ---
sub _readable {
    my ($self) = @_;
    if ($self->{mode} eq 'plain' && !$self->{ssl}) {
        my $n = sysread($self->{sock}, my $chunk, 65536);
        return $self->_close unless $n;      # EOF/err
        $self->{rbuf} .= $chunk;
        if ((my $end = index($self->{rbuf}, "\r\n\r\n")) >= 0) {
            my $head = substr($self->{rbuf}, 0, $end + 4, '');
            my $reply = $self->_handle_line($head);
            if ($self->{mode} eq 'tls') { $self->_write_raw($reply); $self->_begin_tls }
        }
        return;
    }
    $self->_tls_readable if $self->{ssl};
}

# --- Net::SSLeay server handshake driven by EV ---
sub _begin_tls {
    my ($self) = @_;
    my $ctx = $self->{ctx} = Net::SSLeay::CTX_new();
    # SNI callback: mint/install leaf for the requested name
    Net::SSLeay::CTX_set_tlsext_servername_callback($ctx, sub {
        my $ssl = shift;
        my $host = Net::SSLeay::get_servername($ssl) || $self->{connect_host};
        my ($cert, $key) = $self->{ca}->leaf_for($host);
        Net::SSLeay::set_certificate($ssl, $cert);
        Net::SSLeay::set_privatekey($ssl, $key);
    });
    $self->{ca}->apply_to_ctx($ctx, $self->{connect_host});   # default cert
    my $ssl = $self->{ssl} = Net::SSLeay::new($ctx);
    Net::SSLeay::set_fd($ssl, fileno($self->{sock}));
    $self->{handshaking} = 1;
    $self->_pump_accept;
}

sub _pump_accept {
    my ($self) = @_;
    my $rc = Net::SSLeay::accept($self->{ssl});
    if ($rc > 0) { $self->{handshaking} = 0; return }
    my $err = Net::SSLeay::get_error($self->{ssl}, $rc);
    if ($err == Net::SSLeay::ERROR_WANT_READ())  { $self->_want(EV::READ,  \&_pump_accept) }
    elsif ($err == Net::SSLeay::ERROR_WANT_WRITE()){ $self->_want(EV::WRITE, \&_pump_accept) }
    else { $self->_close }
}

# _tls_readable: SSL_read decrypted bytes into rbuf, parse full requests in a
# loop (keep-alive), forward each. Body: read Content-Length/chunked fully
# before forwarding (v1). WANT_READ/WANT_WRITE -> re-arm via _want.
sub _tls_readable { ... }   # implement per the sketch above

# --- forward a parsed request upstream via streaming Multi ---
sub _forward {
    my ($self, $r, %opt) = @_;
    my $host = $self->{connect_host};
    my $url  = $opt{absolute} ? $r->{target} : "https://$host$r->{target}";
    my $fwd  = coherent_headers($r->{headers});
    my $h    = $self->{make_handle}->();
    $self->{inflight} = $h;
    $self->{multi}->add_streaming($h, { method => $r->{method}, url => $url,
        headers => $fwd, body => $r->{body} }, {
        on_headers => sub { my ($status, $hdrs) = @_;
            $self->_write_client(response_head($status, $hdrs)) },
        on_body    => sub { my ($chunk) = @_;
            $self->_write_client($chunk);
            return length($self->{wbuf}) > 262144;   # pause if >256K queued
        },
        on_done    => sub { my ($err) = @_;
            delete $self->{inflight};
            $self->_close if $err && !$self->{wrote_headers};
            # else keep-alive: wait for next request
        },
    });
}

# _write_client: append to wbuf, flush via SSL_write (tls) or syswrite (plain);
# on full-drain, if the upstream was paused, call $self->{multi}->resume($h).
sub _write_client { ... }
sub _write_raw    { ... }   # pre-TLS plaintext write (CONNECT 200)
sub _want         { ... }   # (re)arm the EV io watcher for READ or WRITE with a continuation
sub _close {
    my ($self) = @_;
    $self->{rw} = undef; $self->{ww} = undef;
    if ($self->{inflight}) { eval { $self->{multi}->remove($self->{inflight}) } }
    Net::SSLeay::free($self->{ssl}) if $self->{ssl};
    Net::SSLeay::CTX_free($self->{ctx}) if $self->{ctx};
    close $self->{sock} if $self->{sock};
    $self->{on_close}->($self);
}

1;
```
Implement the `...` methods fully during execution: `_tls_readable` (SSL_read loop + request framing + body read), `_write_client`/`_write_raw` (buffered non-blocking write with a WRITE watcher, resume-on-drain), `_want` (swap the io watcher's event mask + continuation). The Task-3/4 interfaces and the streaming callbacks from Task 2 are all that these depend on.

`$self->{multi}->remove($handle)` in `_close` is the `remove` XSUB added in Task 2 (cancels an in-flight transfer without firing `on_done`).

- [ ] **Step 4: Run (GREEN)** -- `prove -l t/30-connection.t` -- Expected: PASS (CONNECT reply + state).

- [ ] **Step 5: Commit**

```bash
git add lib/Proxy/Impersonate/Connection.pm t/30-connection.t
git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit -m "Proxy::Impersonate::Connection: TLS-terminate + CONNECT + parse + stream-forward"
```

---

## Task 6: Proxy::Impersonate daemon + loopback integration test

Wire listen/accept/EV/config together and prove an end-to-end round-trip against a local origin (no internet).

**Files:**
- Modify: `lib/Proxy/Impersonate.pm` (replace the stub)
- Test: `t/40-integration.t`

**Interfaces:**
- Produces: `Proxy::Impersonate->new(impersonate=>$t, listen=>'127.0.0.1:0', ca_dir=>$d, timeout=>$s, verify=>1, follow_redirects=>0)`, `$p->port`, `$p->ca_bundle_path`, `$p->run` (blocks in EV), `$p->stop`.

- [ ] **Step 1: Write the failing integration test**

Create `t/40-integration.t`:
```perl
use v5.10; use strict; use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Socket; use EV; use Net::SSLeay ();
use Proxy::Impersonate;
# Spin the proxy in-process; a Net::SSLeay client trusting our CA does a CONNECT
# to a local origin the proxy will reach via Curl::Impersonate. Because the
# upstream must be reachable without the internet, point the proxy at a local
# HTTPS origin and set verify=>0 for THIS test only (the origin is self-signed).
plan skip_all => 'integration test; set PROXY_IT=1' unless $ENV{PROXY_IT};
# ... start a local HTTPS origin (fork, Net::SSLeay) that replies 200 "PROXIED";
# ... start Proxy::Impersonate on 127.0.0.1:0 with verify=>0;
# ... a client CONNECTs through the proxy, GETs https://127.0.0.1:<origin>/,
#     and asserts body eq "PROXIED" and that streaming delivered it in chunks.
# (Full harness written during execution -- it needs fork + EV::once timers.)
fail('integration harness not yet written -- see Step 1 notes');   # honest RED
done_testing;
```
Replace this failing stub with the real fork-based harness during execution (origin child, proxy in the parent EV loop via `EV::timer` to stop, client via blocking Net::SSLeay in another fork to avoid in-process deadlock -- the same lesson as EV::WebKit's control tests: never run a blocking client in the same loop as the server).

- [ ] **Step 2: Run (RED)** -- `PROXY_IT=1 prove -l t/40-integration.t` -- Expected: FAIL once the real harness asserts a round-trip.

- [ ] **Step 3: Implement the daemon**

Replace `lib/Proxy/Impersonate.pm`:
```perl
package Proxy::Impersonate;
use v5.10; use strict; use warnings;
use Carp ();
use EV;
use Socket;
use Curl::Impersonate;
use Proxy::Impersonate::CA;
use Proxy::Impersonate::Connection;

our $VERSION = '0.01';

sub new {
    my ($class, %o) = @_;
    my $target = $o{impersonate} or Carp::croak('new: impersonate required');
    my ($host, $port) = ($o{listen} // '127.0.0.1:0') =~ /^(.+):(\d+)$/
        or Carp::croak('new: listen must be host:port');
    my $ca = Proxy::Impersonate::CA->new(ca_dir => $o{ca_dir}
        // Carp::croak('new: ca_dir required'));
    socket(my $srv, PF_INET, SOCK_STREAM, 0) or Carp::croak("socket: $!");
    setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
    bind($srv, sockaddr_in($port, inet_aton($host))) or Carp::croak("bind: $!");
    listen($srv, 128) or Carp::croak("listen: $!");
    $srv->blocking(0);
    my $bound = (sockaddr_in(getsockname($srv)))[0];
    my $self = bless {
        srv => $srv, port => $bound, ca => $ca, target => $target,
        timeout => $o{timeout} // 30, verify => $o{verify} // 1,
        follow => $o{follow_redirects} // 0,
        multi => Curl::Impersonate->multi, conns => {},
    }, $class;
    $self->{aw} = EV::io(fileno($srv), EV::READ, sub { $self->_accept });
    return $self;
}

sub port           { $_[0]{port} }
sub ca_bundle_path { $_[0]{ca}->ca_bundle_path }

sub _accept {
    my ($self) = @_;
    while (accept(my $cli, $self->{srv})) {
        my $conn; $conn = Proxy::Impersonate::Connection->new(
            fd => $cli, ca => $self->{ca}, multi => $self->{multi},
            target => $self->{target},
            make_handle => sub { Curl::Impersonate->new(
                impersonate => $self->{target}, verify => $self->{verify},
                timeout => $self->{timeout},
                ($self->{follow} ? (follow_redirects => 1) : ())) },
            on_close => sub { delete $self->{conns}{$_[0]} },
        );
        $self->{conns}{$conn} = $conn;
        $conn->start;
    }
}

sub run  { EV::run }
sub stop { my ($s) = @_; $s->{aw} = undef; EV::break }

1;
```

- [ ] **Step 4: Run (GREEN)** -- `PROXY_IT=1 prove -l t/40-integration.t` -- Expected: PASS (round-trip body "PROXIED", chunked delivery observed).

- [ ] **Step 5: Commit**

```bash
git add lib/Proxy/Impersonate.pm t/40-integration.t
git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit -m "Proxy::Impersonate: daemon (listen/accept/EV/config) + loopback integration test"
```

---

## Task 7: Live JA4 test + valgrind

**Files:**
- Create: `xt/50-fingerprint.t`

**Interfaces:** Consumes the daemon; asserts the origin-seen JA4 is Chrome's.

- [ ] **Step 1: Write the live test**

Create `xt/50-fingerprint.t`:
```perl
use v5.10; use strict; use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Net::SSLeay ();
use Proxy::Impersonate;
plan skip_all => 'live fingerprint test; set CI_LIVE=1' unless $ENV{CI_LIVE};

my $p = Proxy::Impersonate->new(impersonate => 'chrome131',
    listen => '127.0.0.1:0', ca_dir => tempdir(CLEANUP => 1));
# A Net::SSLeay client trusting $p->ca_bundle_path CONNECTs through the proxy to
# tls.peet.ws:443, GETs /api/all, and reads the JSON. Run the client in a child
# (blocking) while the parent runs EV; assert the response JA4 starts with t13d
# (Chrome) -- the origin saw curl-impersonate, not our proxy's Net::SSLeay.
# (Client harness written during execution.)
fail('live client harness not yet written -- see Step 1 notes');   # honest RED
done_testing;
```
Implement the fork-based client harness during execution; assert `"ja4": "t13d...` in the body proves Chrome's fingerprint reached the origin through the proxy.

- [ ] **Step 2: Run** -- `xvfb-run -a env CI_LIVE=1 prove -l xt/50-fingerprint.t` -- Expected: PASS (Chrome JA4 via the proxy).

- [ ] **Step 3: Valgrind the integration test (real perl)**

Run:
```bash
REALPERL=$(perl -MConfig -e 'print $Config{perlpath}')
PROXY_IT=1 valgrind --leak-check=full --show-leak-kinds=definite \
  --errors-for-leak-kinds=definite --error-exitcode=99 \
  "$REALPERL" -Mblib -Ilib t/40-integration.t
```
Expected: exit 0, `definitely lost: 0 bytes`, `ERROR SUMMARY: 0 errors`. Net::SSLeay X509 objects created per host must be freed on connection close (`X509_free`/`EVP_PKEY_free` in the CA cache teardown, `SSL_free`/`CTX_free` in `_close`); fix any leak the valgrind run reports before committing.

- [ ] **Step 4: Commit**

```bash
git add xt/50-fingerprint.t
git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit -m "Proxy::Impersonate: live JA4-through-proxy test + valgrind-clean integration"
```

---

## Task 8: POD, Changes, README, MANIFEST

**Files:**
- Modify: `lib/Proxy/Impersonate.pm` (POD)
- Create: `Changes`, `README.md`, `MANIFEST.SKIP`; generate `MANIFEST`

- [ ] **Step 1: Add POD** to `Proxy::Impersonate` -- SYNOPSIS (spawn, get `port`/`ca_bundle_path`, point a client at it), `new` options, the coherence story with EV::WebKit (`SSL_CERT_FILE` + `set_proxy`), and the honest ceiling (connection fingerprint only; HTTP + HTTPS-CONNECT, h1/h2; no WebSockets/h3 in v1). Note it requires `Curl::Impersonate` >= 0.02 and `Net::SSLeay`.

- [ ] **Step 2: Changes / README / MANIFEST.SKIP**

`Changes` (0.01 initial). `README.md` (what it is, the 3-sub-project context, install, synopsis). `MANIFEST.SKIP` excluding `^\.git/`, `(^|/)\.gitignore$`, `^\.tmp/`, `^blib/`, `^Makefile$`, `^MYMETA\.`, `^docs/`, `^xt/spike-`. Then `perl Makefile.PL && make manifest`.

- [ ] **Step 3: Full test pass**

Run: `prove -l t/` (unit, no network) then `PROXY_IT=1 CI_LIVE=1 xvfb-run -a prove -l t/ xt/`.
Expected: all `t/` pass; `xt/` pass with network.

- [ ] **Step 4: Commit**

```bash
git add lib/Proxy/Impersonate.pm Changes README.md MANIFEST MANIFEST.SKIP
git -c user.name=vividsnow -c user.email=vividsnow@pm.me commit -m "Proxy::Impersonate: POD, Changes, README, MANIFEST"
```

---

## Self-review notes

- **Spec coverage:** architecture/data-flow (Tasks 5-6), the four components (CA=3, HTTP=4, Connection=5, daemon=6), Net::SSLeay CA+leaf+SNI (3+5), SSL_CERT_FILE trust + the fail-fast gate (1), header coherence (4+5), streaming with backpressure (2 extends sub-project 1; consumed in 5), config/coherence (6), error/lifecycle (5+6), testing incl. the spike, unit, loopback integration, live JA4, valgrind (1,3,4,5,6,7), POD/ceiling (8). Every spec section maps to a task.
- **Linchpin isolated up front:** Task 1 is a pure gate -- if WebKit will not trust the CA via SSL_CERT_FILE, that is known before any proxy code, and the IGNORE fallback is pre-decided.
- **Type consistency:** `add_streaming($handle,\%req,\%cbs)` / `resume($handle)` (Task 2) are used identically in Task 5; `leaf_for($host) -> ($cert,$key)` and `ca_bundle_path` (Task 3) are consumed unchanged in 5/6/7; `parse_request_head`/`body_length`/`coherent_headers`/`response_head` (Task 4) match their Task-5 call sites; the response shape `{status,headers,body}`/`{error,code}` is inherited from Curl::Impersonate.
- **Known soft spots (flagged, not hidden):** exact Net::SSLeay helper names (`P_X509_add_extensions`, `X509_get_subjectAltNames`, `CTX_set_tlsext_servername_callback`, `set_certificate`/`set_privatekey`) are version-sensitive and verified at execution against the installed Net::SSLeay; the `_tls_readable`/`_write_client`/`_want` bodies in Connection.pm are sketched structurally and completed against the Net::SSLeay non-blocking pattern, each covered by the integration + valgrind gates; the live/integration harnesses use fork-based blocking clients (never in the server's EV loop -- the EV::WebKit control-test lesson).
