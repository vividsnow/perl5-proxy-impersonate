package Proxy::Impersonate::Connection;
use v5.10; use strict; use warnings;
use EV;
use Errno qw(EAGAIN EWOULDBLOCK);
use Net::SSLeay ();
use Proxy::Impersonate::HTTP qw(parse_request_head body_length coherent_headers response_head);

# Per-WebKit-connection state machine. States:
#   plain     -- reading plaintext (initial: HTTP proxy request or CONNECT)
#   handshake -- Net::SSLeay server handshake in progress (post-CONNECT)
#   tls       -- reading decrypted requests over the terminated tunnel
# One request is in flight at a time (keep-alive, not pipelining); the upstream
# is driven by the shared Curl::Impersonate::Multi (wired to EV by the daemon).

my $HIWAT = 262144;   # pause upstream when this many bytes are queued to WebKit

sub new {
    my ($class, %o) = @_;
    return bless {
        sock        => $o{fd},
        cert        => $o{cert},          # Proxy::Impersonate::Cert
        multi       => $o{multi},         # Curl::Impersonate::Multi (shared)
        override    => $o{override} // {},# headers forced on every upstream request
        high_entropy => $o{high_entropy} // {},   # high-entropy client hints (Accept-CH-gated)
        hints       => $o{hints} // {},   # shared: host -> { hint-name => 1 }
        make_handle => $o{make_handle},   # sub { Curl::Impersonate->new(...) }
        on_close    => $o{on_close} // sub {},
        state       => 'plain',
        rbuf        => '',
        wbuf        => '',
    }, $class;
}

sub start {
    my ($self) = @_;
    $self->{sock}->blocking(0);
    $self->_arm_read;
    return $self;
}

# --- EV watcher management (one read + one write watcher, armed as needed) ---
sub _arm_read    { my $s = shift; $s->{io_r} ||= EV::io(fileno($s->{sock}), EV::READ,  sub { $s->_readable }) }
sub _arm_write   { my $s = shift; $s->{io_w} ||= EV::io(fileno($s->{sock}), EV::WRITE, sub { $s->_writable }) }
sub _disarm_write { $_[0]{io_w} = undef }

# --- readable: handshake, or decrypt/read into rbuf, then process ---
sub _readable {
    my ($self) = @_;
    return $self->_do_handshake if $self->{state} eq 'handshake';
    if ($self->{ssl}) {
        while (1) {
            my ($got, $rv) = Net::SSLeay::read($self->{ssl}, 32768);
            if (defined $rv && $rv > 0) { $self->{rbuf} .= $got; next }   # drain pending
            my $e = Net::SSLeay::get_error($self->{ssl}, defined $rv ? $rv : -1);
            last if $e == Net::SSLeay::ERROR_WANT_READ();
            if ($e == Net::SSLeay::ERROR_WANT_WRITE()) { $self->_arm_write; last }
            return $self->_close;                      # ZERO_RETURN (EOF) or error
        }
    } else {
        my $n = sysread($self->{sock}, my $data, 32768);
        if (!defined $n) { return if $! == EAGAIN || $! == EWOULDBLOCK; return $self->_close }
        return $self->_close if $n == 0;               # EOF
        $self->{rbuf} .= $data;
    }
    $self->_process;
    # a prior SSL_write that wanted-read retries now that we've fed the SSL layer
    $self->_flush if !$self->{_dead} && length $self->{wbuf};
}

# --- parse + dispatch whole requests from rbuf ---
sub _process {
    my ($self) = @_;
    while (!$self->{_dead} && !$self->{_closing}) {
        return if $self->{inflight};                   # one request at a time
        my $end = index($self->{rbuf}, "\r\n\r\n");
        return if $end < 0;                            # head incomplete
        my $r = parse_request_head(substr($self->{rbuf}, 0, $end + 4));
        return $self->_close unless $r;                # malformed
        if ($self->{state} eq 'plain' && $r->{method} eq 'CONNECT') {
            substr($self->{rbuf}, 0, $end + 4, '');    # consume head
            $self->{connect_host} = $r->{target};      # full authority host:port (curl strips :443)
            $self->_write_raw("HTTP/1.1 200 Connection established\r\n\r\n");
            $self->{state} = 'tls';
            $self->_begin_tls if $self->{cert};        # (test passes cert=>undef)
            return;
        }
        my ($mode, $len) = body_length($r->{headers});
        if ($mode eq 'chunked') {
            # no chunked-request decoder (streaming uploads are out of scope); the
            # body framing is unknown-length, so reject cleanly and close. Consume
            # the head + latch _closing so a partial 411 flush doesn't re-parse the
            # same head (and the leftover chunk bytes) into repeated 411s.
            substr($self->{rbuf}, 0, $end + 4, '');
            $self->{_closing} = 1;
            my $msg = 'chunked request bodies are not supported';
            $self->_write_client(response_head(411,
                { 'content-type' => 'text/plain', 'content-length' => length($msg),
                  'connection' => 'close' }) . $msg);
            $self->{close_after_flush} = 1;
            $self->{response_complete} = 1;
            return $self->_maybe_close_after_flush;
        }
        my $need = $end + 4 + ($mode eq 'length' ? $len : 0);
        return if $mode eq 'length' && length($self->{rbuf}) < $need;   # await body
        substr($self->{rbuf}, 0, $end + 4, '');        # consume head
        my $body = ($mode eq 'length' && $len) ? substr($self->{rbuf}, 0, $len, '') : '';
        $r->{body} = $body;
        $self->_forward($r, absolute => ($self->{state} eq 'plain'));
        return;                                        # inflight set; resume on on_done
    }
}

# --- forward one request upstream and stream the response back ---
sub _forward {
    my ($self, $r, %opt) = @_;
    my $url = $opt{absolute} ? $r->{target} : "https://$self->{connect_host}$r->{target}";
    my $fwd = coherent_headers($r->{headers});
    # forced identity headers (UA + low-entropy client hints) over curl's defaults
    $fwd = { %$fwd, %{ $self->{override} } };
    # high-entropy client hints only for a host that has sent Accept-CH (as Chrome does)
    my ($host) = ($self->{connect_host} // '') =~ /^\[?([^\]:]+)/;
    ($host) = $url =~ m{^https?://\[?([^\]:/]+)} if !$host;
    $self->{_req_host} = $host;
    if ($host && (my $want = $self->{hints}{$host})) {
        $fwd->{$_} = $self->{high_entropy}{$_}
            for grep { exists $self->{high_entropy}{$_} } keys %$want;
    }
    my $h   = $self->{make_handle}->();
    $self->{inflight} = $h;
    $self->{wrote_headers} = 0;
    $self->{response_complete} = 0;
    $self->{close_after_flush} = 0;
    $self->{multi}->add_streaming($h,
        { method => $r->{method}, url => $url, headers => $fwd, body => $r->{body} },
        {
            on_headers => sub {
                my ($status, $hdrs) = @_;
                $self->{wrote_headers} = 1;
                # learn which high-entropy hints this host wants (Accept-CH), so
                # later requests to it carry them -- matching Chrome's behavior
                if (defined $self->{_req_host} && (my $ach = $hdrs->{'accept-ch'})) {
                    # bound memory on a long-running proxy: the per-host map has no
                    # TTL, so clear it if it grows large (hints are cheaply re-learned)
                    %{ $self->{hints} } = () if keys %{ $self->{hints} } > 4096;
                    my $h = ref $ach eq 'ARRAY' ? join(',', @$ach) : $ach;
                    for my $req (split /\s*,\s*/, lc $h) {
                        $self->{hints}{$self->{_req_host}}{$req} = 1
                            if exists $self->{high_entropy}{$req};
                    }
                }
                my %h = %$hdrs;
                delete @h{qw(connection keep-alive transfer-encoding proxy-connection upgrade)};
                # curl delivers a decoded body; if length is unknown, delimit the
                # response to WebKit by closing the connection after it.
                if (!exists $h{'content-length'}) {
                    $h{connection} = 'close';
                    $self->{close_after_flush} = 1;
                }
                $self->_write_client(response_head($status, \%h));
            },
            on_body => sub {
                my ($chunk) = @_;
                return 2 if $self->{_write_dead};                # client gone -> abort upstream
                $self->_write_client($chunk);
                return 2 if $self->{_write_dead};                # write just failed -> abort
                if (length($self->{wbuf}) > $HIWAT) { $self->{paused} = 1; return 1 }
                return 0;
            },
            on_done => sub {
                my ($err) = @_;
                delete $self->{inflight};
                return $self->_close if $self->{_write_dead};    # client's write side died
                if ($err && !$self->{wrote_headers}) {           # failed before any byte
                    my $msg = "upstream error: $err";
                    $self->_write_client(response_head(502,
                        { 'content-type' => 'text/plain', 'content-length' => length($msg),
                          'connection' => 'close' }) . $msg);
                    $self->{close_after_flush} = 1;
                    $self->{response_complete} = 1;
                    return $self->_maybe_close_after_flush;
                }
                return $self->_close if $err;                    # failed mid-stream -> abort
                $self->{response_complete} = 1;
                if ($self->{close_after_flush}) { $self->_maybe_close_after_flush }
                else { $self->_reset_for_next; $self->_process }  # keep-alive
            },
        });
}

sub _reset_for_next {
    my ($self) = @_;
    delete @{$self}{qw(wrote_headers response_complete close_after_flush _write_dead)};
}

sub _maybe_close_after_flush {
    my ($self) = @_;
    $self->_close if $self->{close_after_flush} && $self->{response_complete}
                  && !length($self->{wbuf}) && !$self->{inflight};
}

# --- Net::SSLeay server handshake, EV-driven ---
sub _begin_tls {
    my ($self) = @_;
    my $ctx = $self->{ctx} = Net::SSLeay::CTX_new();
    Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL);
    $self->{cert}->apply_to_ctx($ctx);
    my $ssl = $self->{ssl} = Net::SSLeay::new($ctx);
    Net::SSLeay::set_fd($ssl, fileno($self->{sock}));
    $self->{state} = 'handshake';
    $self->_do_handshake;
}

sub _do_handshake {
    my ($self) = @_;
    my $rc = Net::SSLeay::accept($self->{ssl});
    # On success, drain via _readable (SSL_read loop), not _process: a TLS 1.3
    # client's Finished + first request can coalesce into one segment, leaving the
    # request buffered inside OpenSSL where a bare _process (which only reads rbuf)
    # would never see it -> hang.
    if ($rc > 0) { $self->{state} = 'tls'; $self->_disarm_write; return $self->_readable }
    my $e = Net::SSLeay::get_error($self->{ssl}, $rc);
    if    ($e == Net::SSLeay::ERROR_WANT_READ())  { $self->_disarm_write }   # read watcher already armed
    elsif ($e == Net::SSLeay::ERROR_WANT_WRITE()) { $self->_arm_write }
    else  { $self->_close }
}

# --- writable: continue a handshake, or flush the client write buffer ---
sub _writable {
    my ($self) = @_;
    return $self->_do_handshake if $self->{state} eq 'handshake';
    $self->_flush;
}

sub _write_raw    { my ($self, $d) = @_; $self->{wbuf} .= $d; $self->_flush }   # pre-TLS plaintext
sub _write_client { my ($self, $d) = @_; $self->{wbuf} .= $d; $self->_flush }

# A fatal write to the client: never _close synchronously from here, because
# _flush can run inside an upstream on_body/on_headers callback and _close would
# reentrantly remove() the in-flight handle. Mark the write dead so on_body
# aborts the transfer (curl -> on_done -> safe _close); close directly only when
# no forward is in flight.
sub _fail_write {
    my ($self) = @_;
    $self->{_write_dead} = 1;
    $self->_disarm_write;                          # nothing more to write; don't spin
    if ($self->{inflight}) {
        # wake a paused upstream so on_body sees _write_dead and aborts promptly
        # (instead of waiting for the request timeout)
        if ($self->{paused}) {
            $self->{paused} = 0;
            eval { $self->{multi}->resume($self->{inflight}) };
        }
        return;
    }
    $self->_close;
}

sub _flush {
    my ($self) = @_;
    if (!length $self->{wbuf}) { $self->_disarm_write; return }   # nothing to write; drop the watcher
    my $n;
    if ($self->{ssl}) {
        $n = Net::SSLeay::write($self->{ssl}, $self->{wbuf});
        if (!defined $n || $n <= 0) {
            my $e = Net::SSLeay::get_error($self->{ssl}, defined $n ? $n : -1);
            return $self->_arm_write if $e == Net::SSLeay::ERROR_WANT_WRITE();
            if ($e == Net::SSLeay::ERROR_WANT_READ()) { $self->_disarm_write; return }  # retry on readable
            return $self->_fail_write;
        }
    } else {
        $n = syswrite($self->{sock}, $self->{wbuf});
        if (!defined $n) { return $self->_arm_write if $! == EAGAIN || $! == EWOULDBLOCK; return $self->_fail_write }
    }
    substr($self->{wbuf}, 0, $n, '');
    if (length $self->{wbuf}) { return $self->_arm_write }   # partial; finish later
    $self->_disarm_write;
    if ($self->{paused}) {                                   # room again -> resume upstream
        $self->{paused} = 0;
        $self->{multi}->resume($self->{inflight}) if $self->{inflight};
    }
    $self->_maybe_close_after_flush;
}

sub _close {
    my ($self) = @_;
    return if $self->{_dead};
    $self->{_dead} = 1;
    $self->{io_r} = undef; $self->{io_w} = undef;
    if ($self->{inflight}) { eval { $self->{multi}->remove($self->{inflight}) }; delete $self->{inflight} }
    if ($self->{ssl}) { Net::SSLeay::free($self->{ssl}); undef $self->{ssl} }
    if ($self->{ctx}) { Net::SSLeay::CTX_free($self->{ctx}); undef $self->{ctx} }
    close $self->{sock} if $self->{sock};
    $self->{on_close}->($self);
}

1;
