#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Crypt::XXTEA' );
}

diag( "Testing Crypt::XXTEA $Crypt::XXTEA::VERSION, Perl $], $^X" );
