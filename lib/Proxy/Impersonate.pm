package Proxy::Impersonate;
use v5.10; use strict; use warnings;
use Carp ();
use EV;
use Socket;
use File::Temp ();
use Curl::Impersonate;
use Proxy::Impersonate::Cert;
use Proxy::Impersonate::Connection;

our $VERSION = '0.01';

sub new {
    my ($class, %o) = @_;
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
        timeout => $o{timeout} // 30,
        verify  => defined $o{verify} ? $o{verify} : 1,
        follow  => $o{follow_redirects} // 0,
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
sub _wire_multi {
    my ($self) = @_;
    my $m = $self->{multi};
    $m->set_socket_callback(sub {
        my ($fd, $what) = @_;
        if ($what == 4) { delete $self->{cio}{$fd}; return }   # CURL_POLL_REMOVE
        my $events = 0;
        $events |= EV::READ  if $what & 1;                     # POLL_IN
        $events |= EV::WRITE if $what & 2;                     # POLL_OUT
        $self->{cio}{$fd} = EV::io($fd, $events, sub {
            my (undef, $revents) = @_;
            my $ev = 0;
            $ev |= 1 if $revents & EV::READ;
            $ev |= 2 if $revents & EV::WRITE;
            $ev = 3 unless $ev;                                # fallback: try both
            $m->socket_action($fd, $ev);
        });
    });
    $m->set_timer_callback(sub {
        my ($ms) = @_;
        if ($ms < 0) { undef $self->{ctimer}; return }
        $self->{ctimer} = EV::timer($ms / 1000, 0, sub { $m->socket_action(-1, 0) });
    });
}

sub _accept {
    my ($self) = @_;
    while (accept(my $cli, $self->{srv})) {
        my $conn = Proxy::Impersonate::Connection->new(
            fd    => $cli,
            cert  => $self->{cert},
            multi => $self->{multi},
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

1;
