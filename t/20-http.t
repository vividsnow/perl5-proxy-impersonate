use v5.10; use strict; use warnings;
use Test::More;
use Proxy::Impersonate::HTTP qw(parse_request_head body_length coherent_headers response_head);

# incomplete head -> undef
is(parse_request_head("GET / HTTP/1.1\r\nHost: x"), undef, 'incomplete head is undef');

my $raw = "POST /p?q=1 HTTP/1.1\r\nHost: ex.com\r\nContent-Length: 5\r\n"
        . "Cookie: a=b\r\nUser-Agent: WebKit\r\n\r\nhello";
my $r = parse_request_head($raw);
is($r->{method}, 'POST', 'method parsed');
is($r->{target}, '/p?q=1', 'target parsed');
is($r->{version}, 'HTTP/1.1', 'version parsed');
is(substr($raw, $r->{header_end}), 'hello', 'header_end points at the body');

# header order + case preserved
is_deeply($r->{headers}[0], ['Host', 'ex.com'], 'first header pair preserves case');

my ($mode, $n) = body_length($r->{headers});
is($mode, 'length', 'content-length framing');
is($n, 5, 'content length is 5');

my ($cmode) = body_length([['Transfer-Encoding','chunked']]);
is($cmode, 'chunked', 'chunked framing detected');

my ($nmode) = body_length([['Host','x']]);
is($nmode, 'none', 'no body framing');

my $fwd = coherent_headers($r->{headers});
is($fwd->{cookie}, 'a=b', 'cookie forwarded (lower-cased)');
ok(!exists $fwd->{'user-agent'}, 'user-agent dropped (impersonate template wins)');
ok(!exists $fwd->{host}, 'host dropped (curl sets it from the URL)');

my $head = response_head(200, { 'content-type' => 'text/html', 'x-a' => '1' });
like($head, qr!\AHTTP/1\.1 200 OK\r\n!, 'status line with reason');
like($head, qr/content-type: text\/html\r\n/, 'header line present');
like($head, qr/\r\n\r\n\z/, 'ends with the blank line');
is(response_head(502, {}), "HTTP/1.1 502 Bad Gateway\r\n\r\n", '502 with no headers');

# coherence: forward WebKit's real per-request Sec-Fetch/Accept metadata
{
    my $sub = coherent_headers([
        ['Host','ex.com'], ['Cookie','a=b'],
        ['Sec-Fetch-Site','same-origin'], ['Sec-Fetch-Mode','cors'], ['Sec-Fetch-Dest','empty'],
        ['Accept','*/*'], ['User-Agent','WebKit'],
    ]);
    is($sub->{'sec-fetch-mode'}, 'cors', 'Sec-Fetch-Mode forwarded (not curl navigate)');
    is($sub->{'sec-fetch-dest'}, 'empty', 'Sec-Fetch-Dest forwarded');
    is($sub->{accept}, '*/*', 'Accept synthesized for empty dest (*/*)');
    ok(!defined $sub->{'sec-fetch-user'}, 'Sec-Fetch-User marked for removal on a subresource');
    ok(exists $sub->{'sec-fetch-user'}, '...as an explicit undef (curl "Header:" removal)');
    ok(!defined $sub->{'upgrade-insecure-requests'}, 'UIR marked for removal on a subresource');
    ok(!exists $sub->{'user-agent'}, 'User-Agent still dropped (identity via override_headers)');
}
# a navigation keeps Sec-Fetch-User / UIR that WebKit sent + Chrome document Accept
{
    my $nav = coherent_headers([
        ['Sec-Fetch-Mode','navigate'], ['Sec-Fetch-Dest','document'],
        ['Sec-Fetch-User','?1'], ['Upgrade-Insecure-Requests','1'],
        ['Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],  # WebKit/Safari flavor
    ]);
    is($nav->{'sec-fetch-user'}, '?1', 'Sec-Fetch-User forwarded on a navigation');
    is($nav->{'upgrade-insecure-requests'}, '1', 'UIR forwarded on a navigation');
    like($nav->{accept}, qr/image\/avif.*application\/signed-exchange/,
         'document Accept synthesized to Chrome (not the forwarded Safari value)');
    unlike($nav->{accept}, qr/^text\/html,application\/xhtml\+xml,application\/xml;q=0\.9,\*\/\*/,
           'the Safari-flavored WebKit Accept is NOT forwarded verbatim');
}
# image destination -> Chrome image Accept
{
    my $img = coherent_headers([['Sec-Fetch-Dest','image']]);
    like($img->{accept}, qr{^image/avif,image/webp,image/apng}, 'image dest -> Chrome image Accept');
}
# an iframe/frame navigation uses the SAME Accept as a top-level document (Chrome)
{
    my $ifr = coherent_headers([['Sec-Fetch-Dest','iframe'], ['Accept','*/*']]);
    like($ifr->{accept}, qr/image\/avif.*application\/signed-exchange/,
         'iframe dest -> Chrome document Accept (not the */* it carried)');
    my $frm = coherent_headers([['Sec-Fetch-Dest','frame']]);
    like($frm->{accept}, qr/image\/avif.*application\/signed-exchange/,
         'frame dest -> Chrome document Accept');
}
# an unmapped dest carrying an app-set Accept forwards it (EventSource, fetch)
# instead of flattening to */*, which Chrome also sends and a strict endpoint needs
{
    my $sse = coherent_headers([['Sec-Fetch-Dest','empty'], ['Accept','text/event-stream']]);
    is($sse->{accept}, 'text/event-stream', 'empty dest keeps an app-set Accept (EventSource)');
    my $json = coherent_headers([['Sec-Fetch-Dest','empty'], ['Accept','application/json']]);
    is($json->{accept}, 'application/json', 'empty dest keeps an app-set Accept (fetch JSON)');
    my $bare = coherent_headers([['Sec-Fetch-Dest','empty']]);
    is($bare->{accept}, '*/*', 'empty dest with no request Accept -> */*');
}
# Accept-Language is NOT forwarded (supplied as an identity header in Chrome format)
{
    my $al = coherent_headers([['Accept-Language','en-us, en;q=0.9'], ['Sec-Fetch-Dest','document']]);
    ok(!exists $al->{'accept-language'}, 'Accept-Language not forwarded (identity supplies Chrome format)');
}
# response_head emits one line per value for a repeated header
{
    my $rh = response_head(200, { 'set-cookie' => ['a=1','b=2'], 'content-type' => 'text/html' });
    my @sc = $rh =~ /set-cookie: (\S+)/g;
    is_deeply(\@sc, ['a=1','b=2'], 'multiple Set-Cookie lines emitted');
}
# response_head strips control chars (response-splitting guard)
{
    my $rh = response_head(200, { 'x-evil' => "ok\r\nInjected: 1" });
    unlike($rh, qr/\r\nInjected:/, 'CRLF in an upstream header value cannot split the response');
}

done_testing;
