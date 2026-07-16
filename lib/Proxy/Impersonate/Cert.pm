package Proxy::Impersonate::Cert;
use v5.10; use strict; use warnings;
use Carp ();
use Net::SSLeay ();

BEGIN { Net::SSLeay::initialize() }

# A single persisted self-signed server cert, presented for every host. Under
# the WebKit set_tls_errors_policy(IGNORE) trust model (see the design's
# post-spike revision), WebKit accepts it regardless of host, so no CA and no
# per-host minting are needed.

sub new {
    my ($class, %o) = @_;
    my $dir = $o{cert_dir} or Carp::croak('Cert: cert_dir required');
    -d $dir or mkdir $dir or Carp::croak("Cert: mkdir $dir: $!");
    my $self = bless { dir => $dir }, $class;
    $self->_load_or_generate;
    return $self;
}

sub cert_path { "$_[0]{dir}/cert.pem" }
sub key_path  { "$_[0]{dir}/key.pem" }
sub cert      { $_[0]{cert} }
sub key       { $_[0]{key} }

sub _gen_key {
    my $rsa = Net::SSLeay::RSA_generate_key(2048, 0x10001);
    my $pk  = Net::SSLeay::EVP_PKEY_new();
    Net::SSLeay::EVP_PKEY_assign_RSA($pk, $rsa);
    return $pk;
}

sub _mk_self_signed {
    my ($cn, $pkey, $san) = @_;
    my $x = Net::SSLeay::X509_new();
    Net::SSLeay::X509_set_version($x, 2);
    Net::SSLeay::ASN1_INTEGER_set(Net::SSLeay::X509_get_serialNumber($x), (int(rand(2**31)) | 1));
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notBefore($x), -3600);
    Net::SSLeay::X509_gmtime_adj(Net::SSLeay::X509_get_notAfter($x), 60*60*24*3650);
    Net::SSLeay::X509_set_pubkey($x, $pkey);
    Net::SSLeay::X509_NAME_add_entry_by_txt(
        Net::SSLeay::X509_get_subject_name($x), 'CN', &Net::SSLeay::MBSTRING_UTF8, $cn, -1, 0);
    Net::SSLeay::X509_set_issuer_name($x, Net::SSLeay::X509_get_subject_name($x));   # self
    Net::SSLeay::P_X509_add_extensions($x, $x,
        &Net::SSLeay::NID_basic_constraints => 'CA:FALSE',
        &Net::SSLeay::NID_subject_alt_name  => $san,
        &Net::SSLeay::NID_key_usage         => 'digitalSignature,keyEncipherment',
        &Net::SSLeay::NID_ext_key_usage     => 'serverAuth');
    Net::SSLeay::X509_sign($x, $pkey, Net::SSLeay::EVP_sha256());
    return $x;
}

sub _load_or_generate {
    my ($self) = @_;
    my ($cf, $kf) = ($self->cert_path, $self->key_path);
    if (-r $cf && -r $kf) {
        my $bc = Net::SSLeay::BIO_new_file($cf, 'r');
        $self->{cert} = Net::SSLeay::PEM_read_bio_X509($bc);
        Net::SSLeay::BIO_free($bc);
        my $bk = Net::SSLeay::BIO_new_file($kf, 'r');
        $self->{key} = Net::SSLeay::PEM_read_bio_PrivateKey($bk);
        Net::SSLeay::BIO_free($bk);
        return;
    }
    my $key  = _gen_key();
    my $cert = _mk_self_signed('Proxy::Impersonate', $key, 'DNS:localhost');
    $self->{key} = $key; $self->{cert} = $cert;
    _spew($cf, Net::SSLeay::PEM_get_string_X509($cert), 0644);
    _spew($kf, Net::SSLeay::PEM_get_string_PrivateKey($key), 0600);
}

# Install the cert+key on a Net::SSLeay server SSL_CTX. Uses the persisted
# files via set_cert_and_key (proven in the Task-1 spike).
sub apply_to_ctx {
    my ($self, $ctx) = @_;
    Net::SSLeay::set_cert_and_key($ctx, $self->cert_path, $self->key_path)
        or Carp::croak('Cert: set_cert_and_key failed');
}

sub _spew {
    my ($path, $data, $mode) = @_;
    open my $fh, '>', $path or Carp::croak("Cert: write $path: $!");
    print $fh $data; close $fh;
    chmod $mode, $path if defined $mode;
}

sub DESTROY {
    my ($self) = @_;
    Net::SSLeay::X509_free($self->{cert})     if $self->{cert};
    Net::SSLeay::EVP_PKEY_free($self->{key})  if $self->{key};   # frees the assigned RSA too
}

1;
