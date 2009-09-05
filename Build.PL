use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Crypt::XXTEA',
    license             => 'lgpl',
    dist_author         => q{Ma Bingyao <andot@ujn.edu.cn>},
    dist_version_from   => 'lib/Crypt/XXTEA.pm',
    build_requires => {
        'Test::More' => 0,
    },
    add_to_cleanup      => [ 'Crypt-XXTEA-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
