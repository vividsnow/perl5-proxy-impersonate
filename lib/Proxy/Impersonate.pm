package Proxy::Impersonate;
use v5.10; use strict; use warnings;
use Carp ();
use EV;
use Socket;
use Scalar::Util ();
use File::Temp ();
use Curl::Impersonate;
use Proxy::Impersonate::Cert;
use Proxy::Impersonate::Connection;

our $VERSION = '0.03';

sub new {
    my ($class, %o) = @_;
    # A client that resets mid-response makes a write raise SIGPIPE, whose default
    # disposition terminates the process -- and since this proxy runs in-process
    # with EV::WebKit, that would take the browser down before the graceful abort
    # path runs. Ignore it (standard for a network server).
    $SIG{PIPE} = 'IGNORE';
    my $target = $o{impersonate} or Carp::croak('new: impersonate target required');
    my ($host, $port) = ($o{listen} // '127.0.0.1:0') =~ /^(.+):(\d+)$/
        or Carp::croak('new: listen must be host:port');
    my $cert_dir = $o{cert_dir} // File::Temp::tempdir(CLEANUP => 1);

    socket(my $srv, PF_INET, SOCK_STREAM, 0) or Carp::croak("socket: $!");
    setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
    bind($srv, sockaddr_in($port, inet_aton($host))) or Carp::croak("bind: $!");
    listen($srv, 128) or Carp::croak("listen: $!");
    $srv->blocking(0);
    my $bound = (sockaddr_in(getsockname($srv)))[0];

    my $self = bless {
        srv     => $srv,
        port    => $bound,
        cert    => Proxy::Impersonate::Cert->new(cert_dir => $cert_dir),
        cert_dir=> $cert_dir,
        target  => $target,
        # Is the impersonate target a Chrome family? Decides whether the per-request
        # Accept is synthesized to Chrome's value or WebKit's own (Safari-correct)
        # value is forwarded -- so a Safari target does not present a Chrome Accept.
        chrome  => (($o{chrome} // ($target =~ /chrome/i)) ? 1 : 0),
        timeout => $o{timeout} // 30,
        verify  => defined $o{verify} ? $o{verify} : 1,
        follow  => $o{follow_redirects} // 0,
        override => $o{override_headers} // {},   # forced on every upstream request
        high_entropy => $o{high_entropy_headers} // {}, # added per-host after Accept-CH
        hints    => {},                           # host -> { hint-name => 1 } (Accept-CH seen)
        multi   => Curl::Impersonate->multi,
        conns   => {},
        cio     => {},   # curl fd => EV::io watcher
    }, $class;

    $self->_wire_multi;
    $self->{aw} = EV::io(fileno($srv), EV::READ, sub { $self->_accept });
    return $self;
}

sub port     { $_[0]{port} }
sub cert_dir { $_[0]{cert_dir} }

# Drive Curl::Impersonate::Multi from the EV loop via its socket-action surface.
# The stored callbacks close over $self and the multi; weaken both so they do NOT
# form a reference cycle (multi -> callback -> $self -> $self->{multi} = multi)
# that would keep the multi alive and prevent its DESTROY (curl_multi_cleanup)
# from ever running -- a per-session leak of the handle + its upstream sockets.
sub _wire_multi {
    my ($self) = @_;
    my $m = $self->{multi};
    Scalar::Util::weaken(my $wself = $self);
    Scalar::Util::weaken(my $wm    = $m);
    $m->set_socket_callback(sub {
        my ($fd, $what) = @_;
        return unless $wself && $wm;
        if ($what == 4) { delete $wself->{cio}{$fd}; return }  # CURL_POLL_REMOVE
        my $events = 0;
        $events |= EV::READ  if $what & 1;                     # POLL_IN
        $events |= EV::WRITE if $what & 2;                     # POLL_OUT
        $wself->{cio}{$fd} = EV::io($fd, $events, sub {
            my (undef, $revents) = @_;
            return unless $wm;
            my $ev = 0;
            $ev |= 1 if $revents & EV::READ;
            $ev |= 2 if $revents & EV::WRITE;
            $ev = 3 unless $ev;                                # fallback: try both
            $wm->socket_action($fd, $ev);
        });
    });
    $m->set_timer_callback(sub {
        my ($ms) = @_;
        return unless $wself && $wm;
        if ($ms < 0) { undef $wself->{ctimer}; return }
        $wself->{ctimer} = EV::timer($ms / 1000, 0, sub { $wm->socket_action(-1, 0) if $wm });
    });
}

sub _accept {
    my ($self) = @_;
    while (accept(my $cli, $self->{srv})) {
        my $conn = Proxy::Impersonate::Connection->new(
            fd    => $cli,
            cert  => $self->{cert},
            multi => $self->{multi},
            override => $self->{override},
            chrome => $self->{chrome},
            high_entropy => $self->{high_entropy},
            hints => $self->{hints},
            make_handle => sub {
                Curl::Impersonate->new(
                    impersonate => $self->{target},
                    verify      => $self->{verify},
                    timeout     => $self->{timeout},
                    ($self->{follow} ? (follow_redirects => 1) : ()),
                );
            },
            on_close => sub { delete $self->{conns}{ $_[0] } },
        );
        $self->{conns}{$conn} = $conn;
        $conn->start;
    }
}

sub run  { EV::run }
sub stop { my ($self) = @_; undef $self->{aw}; EV::break(EV::BREAK_ALL) }

# In-process teardown: stop accepting, close active connections, release the
# curl_multi wiring. Unlike stop(), does NOT EV::break -- the caller's shared
# loop keeps running (e.g. EV::WebKit's browser loop).
sub shutdown {
    my ($self) = @_;
    undef $self->{aw};
    my @conns = values %{ $self->{conns} || {} };   # snapshot: _close mutates {conns} via on_close
    $self->{conns} = {};
    for my $c (@conns) { eval { $c->_close } }
    $self->{cio} = {};
    undef $self->{ctimer};
    undef $self->{multi};
    return $self;
}

1;

__END__

=head1 NAME

Proxy::Impersonate -- EV MITM proxy that re-originates with a browser TLS/HTTP2 fingerprint

=head1 SYNOPSIS

    use EV;
    use Proxy::Impersonate;

    my $proxy = Proxy::Impersonate->new(
        impersonate => 'chrome131',
        listen      => '127.0.0.1:0',   # ephemeral port
        cert_dir    => '/path/to/ca',   # persists the self-signed cert
    );
    printf "proxy on 127.0.0.1:%d\n", $proxy->port;
    $proxy->run;   # EV loop

A client (or EV::WebKit) uses it as an HTTP/HTTPS forward proxy. For HTTPS the
client issues C<CONNECT host:443>; the proxy terminates that TLS with its own
cert, then re-originates the request upstream through L<Curl::Impersonate> so the
origin sees the chosen browser's TLS (JA3/JA4) and HTTP/2 (Akamai) fingerprint.

=head1 DESCRIPTION

EV::WebKit cannot present a browser's connection fingerprint itself -- WebKitGTK
speaks GnuTLS/libsoup. This proxy sits in front of it: it MITMs WebKit's TLS on
localhost, reads the plaintext request, and sends it upstream with a real
browser's handshake via C<libcurl-impersonate>. The origin's TLS/HTTP2
fingerprint therefore matches the impersonated browser, not WebKit.

It is an HTTP client, not a browser: it reproduces the B<connection>
fingerprint only. HTTP/3 and WebSockets are out of scope in this release, as are
streaming request uploads.

B<Header-order ceiling:> curl-impersonate reproduces the target's TLS (JA3/JA4)
and HTTP/2 (Akamai) fingerprints exactly, and template headers keep their
positions. But headers the proxy adds that are not in the template (Cookie,
Referer, and the high-entropy Sec-CH-UA hints) are appended after the template
block rather than in the browser's exact positions, so a header-order-only hash
(e.g. JA4H) will not match on requests carrying them. The dominant fingerprints
(JA3/JA4/Akamai) are unaffected.

B<Priority ceiling:> the proxy synthesizes a per-destination Accept, but the
HTTP/2 request priority (the C<priority> header and any PRIORITY_UPDATE frames)
comes from curl-impersonate's static template, not from the resource type. Chrome
varies urgency per resource; the proxy does not, so a resource-priority-aware
fingerprinter could tell subresources apart. This lives in curl-impersonate's
protocol layer, not in a header the proxy re-writes.

=head1 TRUST MODEL

WebKitGTK 6.0 exposes no way to trust a custom CA (its network process honors
neither C<SSL_CERT_FILE> nor a settable C<GTlsDatabase>; this was verified by a
spike). So the proxy presents a single self-signed cert and the WebKit side is
told to accept it:

    # on the EV::WebKit network session (sub-project 3 wires this):
    $session->set_tls_errors_policy('ignore');
    $browser->set_proxy("http://127.0.0.1:" . $proxy->port);

This is safe: the WebKit-to-proxy hop is localhost, and the proxy re-verifies the
real origin certificate upstream (C<< verify => 1 >>, the default).

=head1 METHODS

=head2 new

    my $proxy = Proxy::Impersonate->new(%opt);

=over 4

=item impersonate => $target

Required. The L<Curl::Impersonate> target (e.g. C<'chrome131'>) applied to every
upstream request. Keep it coherent with EV::WebKit's C<fingerprint> profile.

=item listen => 'host:port'

Bind address; default C<'127.0.0.1:0'> (an ephemeral port, reported by L</port>).

=item cert_dir => $path

Where the self-signed cert is persisted. Defaults to a temporary directory.

=item timeout => $seconds

Per-request upstream timeout. Default 30.

=item verify => $bool

Verify the real origin's certificate upstream. Default true; leave it on.

=item follow_redirects => $bool

Whether the upstream client follows redirects. Default false -- the browser
handles 3xx itself, so the proxy forwards them.

=back

=head2 port

The bound listen port (useful with C<listen =E<gt> '...:0'>).

=head2 cert_dir

The directory holding the self-signed cert.

=head2 run

Run the EV loop. Blocks until L</stop> or C<EV::break>.

=head2 stop

Stop accepting and break the EV loop.

=head1 REQUIREMENTS

L<Curl::Impersonate> 0.02 or later (streaming callbacks), L<Net::SSLeay>, L<EV>.

=head1 SEE ALSO

L<Curl::Impersonate>, L<EV::WebKit>

=head1 AUTHOR

vividsnow

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
