use v5.10; use strict; use warnings;
# Fail-fast spike (Task 1): does WebKit's network process trust a CA that is
# present ONLY via SSL_CERT_FILE? Mint a CA + a leaf for "localhost", run a tiny
# Net::SSLeay HTTPS server presenting the leaf, point EV::WebKit at it with
# SSL_CERT_FILE=<bundle-with-our-CA>, and load the page. PASS = no TLS error.
# Run: xvfb-run -a perl -I../EV-WebKit/lib xt/spike-ssl-cert-file.pl
use Net::SSLeay ();
use Socket;
use File::Temp qw(tempdir);

Net::SSLeay::initialize();
my $dir = tempdir(CLEANUP => 1);

sub gen_key {
    my $rsa = Net::SSLeay::RSA_generate_key(2048, 0x10001);
    my $pk  = Net::SSLeay::EVP_PKEY_new();
    Net::SSLeay::EVP_PKEY_assign_RSA($pk, $rsa);
    return $pk;
}
sub mk_cert {
    my (%a) = @_;
    my $x = Net::SSLeay::X509_new();
    Net::SSLeay::X509_set_version($x, 2);
    Net::SSLeay::ASN1_INTEGER_set(Net::SSLeay::X509_get_serialNumber($x),
        $a{serial} // (int(rand(2**31)) | 1));
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notBefore($x), -3600);
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notAfter($x), 60*60*24*825);
    Net::SSLeay::X509_set_pubkey($x, $a{pkey});
    my $nm = Net::SSLeay::X509_get_subject_name($x);
    Net::SSLeay::X509_NAME_add_entry_by_txt($nm, 'CN', &Net::SSLeay::MBSTRING_UTF8, $a{cn}, -1, 0);
    my $icert = $a{issuer_cert} // $x;
    Net::SSLeay::X509_set_issuer_name($x, Net::SSLeay::X509_get_subject_name($icert));
    if ($a{ca}) {
        Net::SSLeay::P_X509_add_extensions($x, $icert,
            &Net::SSLeay::NID_basic_constraints => 'critical,CA:TRUE',
            &Net::SSLeay::NID_key_usage         => 'critical,keyCertSign,cRLSign');
    } else {
        Net::SSLeay::P_X509_add_extensions($x, $icert,
            &Net::SSLeay::NID_basic_constraints => 'CA:FALSE',
            &Net::SSLeay::NID_subject_alt_name  => $a{san},   # full SAN, e.g. "IP:127.0.0.1"
            &Net::SSLeay::NID_key_usage         => 'digitalSignature,keyEncipherment',
            &Net::SSLeay::NID_ext_key_usage     => 'serverAuth');
    }
    Net::SSLeay::X509_sign($x, $a{issuer_key} // $a{pkey}, Net::SSLeay::EVP_sha256());
    return $x;
}

my $ca_key  = gen_key();
my $ca_cert = mk_cert(cn => 'Proxy::Impersonate spike CA', pkey => $ca_key, ca => 1);
my $lf_key  = gen_key();
my $lf_cert = mk_cert(cn => '127.0.0.1', pkey => $lf_key, san => 'IP:127.0.0.1',
                      issuer_cert => $ca_cert, issuer_key => $ca_key);

my ($sys) = grep { -r } qw(/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt);
my $bundle = "$dir/bundle.pem";
open my $bh, '>', $bundle or die $!;
if ($sys) { open my $s, '<', $sys or die $!; local $/; print {$bh} scalar(<$s>); close $s }
print $bh Net::SSLeay::PEM_get_string_X509($ca_cert);
close $bh;
my ($cf, $kf) = ("$dir/leaf.crt", "$dir/leaf.key");
open my $c, '>', $cf; print $c Net::SSLeay::PEM_get_string_X509($lf_cert); close $c;
open my $k, '>', $kf; print $k Net::SSLeay::PEM_get_string_PrivateKey($lf_key); close $k;

# listen on 127.0.0.1:0
socket(my $srv, PF_INET, SOCK_STREAM, 0) or die "socket: $!";
setsockopt($srv, SOL_SOCKET, SO_REUSEADDR, 1);
bind($srv, sockaddr_in(0, inet_aton('127.0.0.1'))) or die "bind: $!";
listen($srv, 5) or die "listen: $!";
my $port = (sockaddr_in(getsockname($srv)))[0];

# fork the HTTPS server child BEFORE any WebKit/GI init
my $pid = fork // die "fork: $!";
if ($pid == 0) {
    my $ctx = Net::SSLeay::CTX_new();
    Net::SSLeay::set_cert_and_key($ctx, $cf, $kf);
    for (1..3) {                                  # answer a few connections
        accept(my $cli, $srv) or last;
        my $ssl = Net::SSLeay::new($ctx);
        Net::SSLeay::set_fd($ssl, fileno($cli));
        if (Net::SSLeay::accept($ssl) > 0) {
            Net::SSLeay::read($ssl);
            Net::SSLeay::write($ssl,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
              . "Content-Length: 22\r\nConnection: close\r\n\r\n<html><body>ok</body>");
        }
        Net::SSLeay::free($ssl); close $cli;
    }
    exit 0;
}
close $srv;

# also prepare a hashed CA dir for the SSL_CERT_DIR attempt
my $certdir = "$dir/certs"; mkdir $certdir;
open my $co, '>', "$dir/ca-only.crt"; print $co Net::SSLeay::PEM_get_string_X509($ca_cert); close $co;
chomp(my $hash = `openssl x509 -hash -noout -in "$dir/ca-only.crt" 2>/dev/null`);
if ($hash) { require File::Copy; File::Copy::copy("$dir/ca-only.crt", "$certdir/$hash.0") }

# point WebKit at the bundle and load the page
$ENV{SSL_CERT_FILE} = $bundle;
$ENV{SSL_CERT_DIR}  = $certdir;   # second attempt: hashed dir (some GnuTLS builds use this)
require EV;
require EV::WebKit;
my $verdict;
my $b = eval { EV::WebKit->new(window => [400,300]) };
unless ($b) { warn "SPIKE SKIP: EV::WebKit unavailable: $@"; kill 'TERM', $pid; exit 2 }
$b->go("https://127.0.0.1:$port/", sub {
    my (undef, $err) = @_;
    $verdict = $err ? "err:$err" : 'ok';
    EV::break();
});
my $timer = EV::timer(30, 0, sub { $verdict //= 'timeout'; EV::break() });
EV::run();
kill 'TERM', $pid; waitpid($pid, 0);

if (($verdict // '') eq 'ok') {
    say "SPIKE PASS: WebKit trusted the CA via SSL_CERT_FILE";
    exit 0;
} else {
    say "SPIKE FAIL (verdict=", ($verdict // 'undef'),
        "): fall back to set_tls_errors_policy(IGNORE)";
    exit 1;
}
