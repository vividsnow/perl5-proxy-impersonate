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

done_testing;
