use v5.10; use strict; use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Net::SSLeay ();
use Proxy::Impersonate::Cert;

my $dir = tempdir(CLEANUP => 1);
my $c = Proxy::Impersonate::Cert->new(cert_dir => $dir);
ok(-r $c->cert_path && -r $c->key_path, 'cert+key persisted to disk');
ok($c->cert, 'cert object available');
ok($c->key,  'key object available');

# self-signed: issuer == subject
is(Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_issuer_name($c->cert)),
   Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($c->cert)),
   'cert is self-signed (issuer == subject)');

# stable across instances (persisted, not regenerated)
my $pem1 = do { open my $f, '<', $c->cert_path; local $/; <$f> };
my $c2   = Proxy::Impersonate::Cert->new(cert_dir => $dir);
my $pem2 = do { open my $f, '<', $c2->cert_path; local $/; <$f> };
is($pem1, $pem2, 'cert is stable across instances (persisted)');

# key file is private
my $mode = (stat $c->key_path)[2] & 07777;
is($mode & 077, 0, 'key file is not group/other readable');

# applies to a server CTX without error
my $ctx = Net::SSLeay::CTX_new();
ok(eval { $c->apply_to_ctx($ctx); 1 }, 'apply_to_ctx succeeds') or diag($@);

done_testing;
