use v5.10; use strict; use warnings;
use Test::More;
use Socket;
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
    is($conn->{connect_host}, 'ex.com', 'CONNECT host captured');
    is($conn->{state}, 'tls', 'state flipped to tls after CONNECT');
    sysread($client, my $reply, 128);
    like($reply, qr!\AHTTP/1\.1 200 Connection established\r\n\r\n!, 'CONNECT gets a 200 established reply');
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

done_testing;
