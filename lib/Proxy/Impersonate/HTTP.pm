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

# Forward WebKit's real per-request headers so the origin sees a coherent request
# CONTEXT, not curl-impersonate's static navigation defaults. curl's template
# hard-codes Sec-Fetch-Mode: navigate / Sec-Fetch-Dest: document / Accept:
# text/html on EVERY request, which makes every subresource (image/script/XHR)
# look like a top-level document load -- a glaring tell. WebKit computes correct
# per-request Sec-Fetch-* + Accept, so forwarding them (they override the template
# in place) fixes it. The User-Agent/Sec-CH-UA identity headers are supplied
# separately via override_headers.
my %FORWARD = map { $_ => 1 } qw(
    cookie referer origin content-type authorization
    sec-fetch-site sec-fetch-mode sec-fetch-dest accept accept-language
);
# Headers a real browser sends only on navigations / user-activated requests: if
# WebKit did not send one, strip curl's template default (undef => "Header;") so a
# subresource does not carry e.g. Sec-Fetch-User: ?1 or Upgrade-Insecure-Requests.
my %CONDITIONAL = map { $_ => 1 } qw(sec-fetch-user upgrade-insecure-requests);

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

# The request headers to forward upstream, lower-cased. A value of undef means
# "remove this header from the impersonate template".
sub coherent_headers {
    my ($pairs) = @_;
    my (%out, %seen);
    for (@$pairs) {
        my $k = lc $_->[0];
        if    ($FORWARD{$k})     { $out{$k} = $_->[1] }
        elsif ($CONDITIONAL{$k}) { $out{$k} = $_->[1]; $seen{$k} = 1 }
    }
    $out{$_} = undef for grep { !$seen{$_} } keys %CONDITIONAL;
    return \%out;
}

# Serialise a response status line + headers + terminating blank line. A header
# whose value is an arrayref (a repeated header, e.g. Set-Cookie) emits one line
# per value. Control chars in names/values are stripped (response-splitting guard).
sub response_head {
    my ($status, $headers) = @_;
    my $reason = $REASON{$status} // 'Status';
    my $out = "HTTP/1.1 $status $reason\r\n";
    for my $k (sort keys %$headers) {
        my $v = $headers->{$k};
        next unless defined $v;
        (my $ck = $k) =~ tr/\r\n\0//d;
        for my $val (ref $v eq 'ARRAY' ? @$v : $v) {
            next unless defined $val;
            (my $cv = $val) =~ tr/\r\n\0//d;
            $out .= "$ck: $cv\r\n";
        }
    }
    $out .= "\r\n";
    return $out;
}

1;
