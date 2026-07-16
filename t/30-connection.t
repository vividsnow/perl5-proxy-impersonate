use v5.10; use strict; use warnings;
use Test::More;
use Socket;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Proxy::Impersonate::Connection;

# Fake Multi: capture add_streaming calls; no-op resume/remove.
{
    package FakeMulti;
    sub new { bless { calls => [] }, shift }
    sub add_streaming { my ($s, $h, $req, $cbs) = @_; push @{$s->{calls}}, { req => $req, cbs => $cbs } }
    sub resume {}
    sub remove {}
}

# --- CONNECT: reply 200, capture host, flip to tls state (cert=>undef: no TLS) ---
{
    socketpair(my $client, my $srv, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    my $conn = Proxy::Impersonate::Connection->new(
        fd => $srv, cert => undef, multi => FakeMulti->new,
        make_handle => sub { bless {}, 'FakeHandle' }, on_close => sub {},
    );
    $conn->{rbuf} = "CONNECT ex.com:443 HTTP/1.1\r\nHost: ex.com:443\r\n\r\n";
    $conn->_process;
    is($conn->{connect_host}, 'ex.com:443', 'CONNECT authority captured (host:port)');
    is($conn->{state}, 'tls', 'state flipped to tls after CONNECT');
    sysread($client, my $reply, 128);
    like($reply, qr!\AHTTP/1\.1 200 Connection established\r\n\r\n!, 'CONNECT gets a 200 established reply');
}

# --- a CONNECT that COALESCES an optimistic ClientHello (bytes after the head) is
#     closed, not left to stall: set_fd cannot see TLS bytes already buffered in rbuf ---
{
    socketpair(my $client, my $srv, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    my $closed = 0;
    my $conn = Proxy::Impersonate::Connection->new(
        fd => $srv, cert => undef, multi => FakeMulti->new,
        make_handle => sub { bless {}, 'FakeHandle' }, on_close => sub { $closed = 1 },
    );
    # CONNECT head immediately followed by (pretend) TLS ClientHello record bytes
    $conn->{rbuf} = "CONNECT ex.com:443 HTTP/1.1\r\nHost: ex.com:443\r\n\r\n\x16\x03\x01\x00\x05hello";
    $conn->_process;
    ok($conn->{_dead}, 'a coalesced CONNECT+ClientHello is closed (not left to stall 120s)');
    ok($closed, 'on_close fired for the coalesced-CONNECT case');
    isnt($conn->{state} // '', 'tls', 'did not flip to tls / start a doomed handshake');
}

# --- a tunnelled GET maps to https://<host><target> with coherent headers ---
{
    socketpair(my $client, my $srv, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    my $fm = FakeMulti->new;
    my $conn = Proxy::Impersonate::Connection->new(
        fd => $srv, cert => undef, multi => $fm,
        make_handle => sub { bless {}, 'FakeHandle' }, on_close => sub {},
    );
    $conn->{state} = 'tls';
    $conn->{connect_host} = 'ex.com';
    $conn->{rbuf} = "GET /p?x=1 HTTP/1.1\r\nHost: ex.com\r\nCookie: a=b\r\nUser-Agent: WK\r\n\r\n";
    $conn->_process;
    is(scalar @{$fm->{calls}}, 1, 'one upstream request queued');
    my $req = $fm->{calls}[0]{req};
    is($req->{url}, 'https://ex.com/p?x=1', 'reconstructed absolute https URL');
    is($req->{method}, 'GET', 'method forwarded');
    is($req->{headers}{cookie}, 'a=b', 'cookie forwarded');
    ok(!exists $req->{headers}{'user-agent'}, 'user-agent dropped (template owns it)');
    ok($conn->{inflight}, 'request marked in-flight');
}

# --- a POST body is read from rbuf and forwarded ---
{
    socketpair(my $client, my $srv, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    my $fm = FakeMulti->new;
    my $conn = Proxy::Impersonate::Connection->new(
        fd => $srv, cert => undef, multi => $fm,
        make_handle => sub { bless {}, 'FakeHandle' }, on_close => sub {},
    );
    $conn->{state} = 'tls'; $conn->{connect_host} = 'ex.com';
    $conn->{rbuf} = "POST /api HTTP/1.1\r\nHost: ex.com\r\nContent-Length: 5\r\n\r\nhello";
    $conn->_process;
    is($fm->{calls}[0]{req}{body}, 'hello', 'request body forwarded');
}

# --- override headers are forced onto the upstream request ---
{
    socketpair(my $client, my $srv, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    my $fm = FakeMulti->new;
    my $conn = Proxy::Impersonate::Connection->new(
        fd => $srv, cert => undef, multi => $fm,
        override => { 'user-agent' => 'WinChrome/131', 'sec-ch-ua-platform' => '"Windows"' },
        make_handle => sub { bless {}, 'FakeHandle' }, on_close => sub {},
    );
    $conn->{state} = 'tls'; $conn->{connect_host} = 'ex.com';
    $conn->{rbuf} = "GET / HTTP/1.1\r\nHost: ex.com\r\nUser-Agent: WebKit\r\nCookie: a=b\r\n\r\n";
    $conn->_process;
    my $h = $fm->{calls}[0]{req}{headers};
    is($h->{'user-agent'}, 'WinChrome/131', 'override replaces the UA');
    is($h->{'sec-ch-ua-platform'}, '"Windows"', 'override injects the platform client-hint');
    is($h->{cookie}, 'a=b', 'non-overridden request headers still forwarded');
}

# --- deferred TLS: when pre-TLS plaintext (e.g. a slow-client response tail) is
#     still queued at CONNECT time, the handshake starts only after _flush drains
#     it, not immediately -- else the handshake state strands the queued 200 ---
SKIP: {
    skip 'needs Net::SSLeay for a real cert', 3
        unless eval { require Net::SSLeay; require Proxy::Impersonate::Cert; require File::Temp; 1 };
    my $cert = Proxy::Impersonate::Cert->new(cert_dir => File::Temp::tempdir(CLEANUP => 1));
    socketpair(my $client, my $srv, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or die "socketpair: $!";
    fcntl($srv, F_SETFL, (fcntl($srv, F_GETFL, 0) | O_NONBLOCK)) or die "fcntl: $!";
    my $conn = Proxy::Impersonate::Connection->new(
        fd => $srv, cert => $cert, multi => FakeMulti->new,
        make_handle => sub {}, on_close => sub {},
    );
    $conn->{connect_host} = 'ex.com:443';
    $conn->{state} = 'tls';
    $conn->{wbuf} = "HTTP/1.1 200 Connection established\r\n\r\n";
    $conn->{_tls_pending} = 1;
    ok(!$conn->{ctx}, 'deferred: TLS not started while pre-TLS plaintext is queued');
    $conn->_flush;   # drains wbuf to the peer -> starts the deferred handshake
    ok($conn->{ctx}, 'deferred TLS handshake starts once the pre-TLS plaintext flushes');
    ok(!$conn->{_tls_pending}, '_tls_pending cleared after the handshake begins');
    $conn->_close;
}

done_testing;
