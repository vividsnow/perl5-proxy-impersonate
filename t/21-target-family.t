use v5.10; use strict; use warnings;
use Test::More;
use File::Temp qw(tempdir);
BEGIN { plan skip_all => 'needs Net::SSLeay' unless eval { require Net::SSLeay; 1 } }
require Proxy::Impersonate;

# The daemon derives the Accept-synthesis "chrome family" flag from the impersonate
# target: a Chrome target gets Chrome per-destination Accepts, a Safari target
# forwards WebKit's own (Safari-correct) Accept. A shared cert_dir keeps the
# per-proxy cert generation to one keypair.
my $dir = tempdir(CLEANUP => 1);
my %WANT = (
    chrome131         => 1,
    chrome131_android => 1,
    safari18_0        => 0,
    safari18_0_ios    => 0,
);
for my $target (sort keys %WANT) {
    my $p = Proxy::Impersonate->new(impersonate => $target, listen => '127.0.0.1:0', cert_dir => $dir);
    is($p->{chrome}, $WANT{$target}, "target $target -> chrome family = $WANT{$target}");
}

# an explicit chrome => flag overrides the target heuristic (for a custom target
# the /chrome/ match would misclassify)
my $p = Proxy::Impersonate->new(impersonate => 'edge131', listen => '127.0.0.1:0', cert_dir => $dir, chrome => 1);
is($p->{chrome}, 1, 'explicit chrome => 1 overrides the target-name heuristic');

done_testing;
