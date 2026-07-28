use v5.10; use strict; use warnings;
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME             => 'Proxy::Impersonate',
    VERSION_FROM     => 'lib/Proxy/Impersonate.pm',
    ABSTRACT         => 'EV MITM proxy that re-originates with a browser TLS/HTTP2 fingerprint',
    AUTHOR           => 'vividsnow',
    LICENSE          => 'perl_5',
    MIN_PERL_VERSION => '5.010',
    PREREQ_PM        => { 'EV' => 0, 'Net::SSLeay' => '1.85', 'Curl::Impersonate' => '0.03' },
    TEST_REQUIRES    => { 'Test::More' => 0 },
    META_MERGE       => {
        'meta-spec' => { version => 2 },
        resources   => { repository => { type=>'git', url=>'https://github.com/vividsnow/perl5-proxy-impersonate.git', web=>'https://github.com/vividsnow/perl5-proxy-impersonate' } },
    },
);
