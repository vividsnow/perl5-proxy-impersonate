package Proxy::Impersonate::HTTP;
use v5.10; use strict; use warnings;
use Exporter 'import';
our @EXPORT_OK = qw(parse_request_head body_length coherent_headers response_head);

my %REASON = (
    200=>'OK', 201=>'Created', 204=>'No Content',
    301=>'Moved Permanently', 302=>'Found', 303=>'See Other',
    304=>'Not Modified', 307=>'Temporary Redirect', 308=>'Permanent Redirect',
    400=>'Bad Request', 401=>'Unauthorized', 403=>'Forbidden', 404=>'Not Found',
    500=>'Internal Server Error', 502=>'Bad Gateway', 503=>'Service Unavailable',
    504=>'Gateway Timeout',
);

# Keep only per-request state; the impersonate template supplies identity
# headers (User-Agent/Accept/sec-ch-ua/...) with the right order.
my %FORWARD = map { $_ => 1 } qw(cookie referer origin content-type authorization);

# Parse an HTTP/1.x request head. Returns undef if the head is incomplete
# (no CRLFCRLF yet), else a hashref. headers is an ordered arrayref of [k,v]
# pairs, preserving case and order as received.
sub parse_request_head {
    my ($buf) = @_;
    my $end = index($buf, "\r\n\r\n");
    return undef if $end < 0;
    my $head = substr($buf, 0, $end);
    my ($line, @lines) = split /\r\n/, $head;
    return undef unless defined $line;
    my ($method, $target, $version) = $line =~ m{^(\S+)\s+(\S+)\s+(HTTP/\d\.\d)$}
        or return undef;
    my @pairs;
    for my $h (@lines) {
        my ($k, $v) = $h =~ /^([^:]+):[ \t]*(.*?)[ \t]*$/ or next;
        push @pairs, [$k, $v];
    }
    return {
        method => $method, target => $target, version => $version,
        headers => \@pairs, header_end => $end + 4,
    };
}

sub _get {
    my ($pairs, $name) = @_;
    $name = lc $name;
    for (@$pairs) { return $_->[1] if lc($_->[0]) eq $name }
    return undef;
}

# How the request/response body is framed. Returns ('chunked') or
# ('length', $n) or ('none').
sub body_length {
    my ($pairs) = @_;
    my $te = _get($pairs, 'transfer-encoding');
    return ('chunked') if $te && $te =~ /chunked/i;
    my $cl = _get($pairs, 'content-length');
    return ('length', $cl + 0) if defined $cl && $cl =~ /^\d+$/;
    return ('none');
}

# The subset of request headers to forward upstream, lower-cased.
sub coherent_headers {
    my ($pairs) = @_;
    my %out;
    for (@$pairs) {
        my $k = lc $_->[0];
        $out{$k} = $_->[1] if $FORWARD{$k};
    }
    return \%out;
}

# Serialise a response status line + headers + terminating blank line.
sub response_head {
    my ($status, $headers) = @_;
    my $reason = $REASON{$status} // 'Status';
    my $out = "HTTP/1.1 $status $reason\r\n";
    $out .= "$_: $headers->{$_}\r\n" for sort keys %$headers;
    $out .= "\r\n";
    return $out;
}

1;
