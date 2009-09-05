#/**********************************************************\
#|                                                          |
#| The implementation of PHPRPC Protocol 3.0                |
#|                                                          |
#| xxtea.pm                                                 |
#|                                                          |
#| Release 3.0.0 beta                                       |
#| Copyright (c) 2005-2007 by Team-PHPRPC                   |
#|                                                          |
#| WebSite:  http://www.phprpc.org/                         |
#|           http://www.phprpc.net/                         |
#|           http://www.phprpc.com/                         |
#|           http://sourceforge.net/projects/php-rpc/       |
#|                                                          |
#| Author:   Ma Bingyao <andot@ujn.edu.cn>                  |
#|                                                          |
#| This file may be distributed and/or modified under the   |
#| terms of the GNU Lesser General Public License (LGPL)    |
#| version 3.0 as published by the Free Software Foundation |
#| and appearing in the included file LICENSE.              |
#|                                                          |
#\**********************************************************/
#
# XXTEA encryption arithmetic module.
#
# Copyright (C) 2006-2007 Ma Bingyao <andot@ujn.edu.cn>
# Version:      2.00
# LastModified: Nov 7, 2007
# This library is free.  You can redistribute it and/or modify it.
#
# Module practically entirely rewritten to work with known test vectors
# on 32-bit and 64-bit platforms by Brian Kurle <bk@travelingbits.com>
#

package Crypt::XXTEA;

use bytes;
use strict;
use Exporter;
use vars qw($VERSION @ISA @EXPORT);

$VERSION     = 2.00;
@ISA         = qw(Exporter);
@EXPORT      = qw(xxtea_encrypt xxtea_decrypt);

*encrypt = \&xxtea_encrypt;
*decrypt = \&xxtea_decrypt;

sub _str2long {
    my ($s, $w) = @_;
    my @v = unpack("V*", $s. "\0"x((4 - length($s) % 4) & 3));
    if ($w) {
        $v[@v] = length($s);
    }
    return @v;
}

sub xxtea_encrypt {
    my ($s, $k) = @_;
    if ($s eq "") {
        return "";
    }
    my @v = _str2long($s, 1);
    my @k = _str2long($k, 0);
    if (@k < 4) {
        for (my $i = @k; $i < 4; $i++) {
            $k[$i] = 0;
        }
    }

    my $n = $#v;
    die "n = $n\n" if $n < 2;
    my $z = $v[$n-1];
    my $y = $v[0];
    my $delta = 0x9E3779B9;
    use integer;
    my $q = 6 + 52 / $n;
    no integer;
    my $sum = 0;
    my $e = 0;
    my $p = 0;
    my $mx = 0;
    while ($q-- > 0) {

        $sum = ($sum + $delta) % 4294967296;    # See comment below
        $e = $sum >> 2 & 3;
        for ($p = 0; $p < $n-1; $p++) {
            
            $y = $v[$p + 1];

            # The original equation is ((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z))
            # Unfortunately, there is screwiness with Perl on multiple levels
            # 1)  bitwise operations work only on processor word size, BUT
            # 2)  arithemtic operations appear to dishonor processor word size and
            #     do whatever the heck they please.
            # 
            # So, after the XOR that includes an upshift, perform a module to 
            # fetch just the 32-bit word.  No, Perl returns a 0xFFFFFFFF if the 
            # word size exceeds 32-bits on a 32-bit implementation when you attempt
            # to do the obvious of perform an AND operation to mask it off.  But the
            # modulo operation is permitted and works (go figure).
            #
            # Thus, modulo is used to mask extra bits whenever they may potentially
            # occur:  left shift operations and additions
            #
            # This has been wound back to a single one liner again, but it took 
            # several hours of it totally unwound to get it right!!
            $mx = (((($z>>5^$y<<2) % 4294967296) + (($y>>3^$z<<4) % 4294967296)) % 4294967296) ^ ((($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z)) % 4294967296); 

            $z = $v[$p] = ($v[$p] + $mx) % 4294967296;

        }
        $y = $v[0];
        $mx = (((($z>>5^$y<<2) % 4294967296) + (($y>>3^$z<<4) % 4294967296)) % 4294967296) ^ ((($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z)) % 4294967296); 
        $v[$n-1] = ($v[$n-1] + $mx) % 4294967296;
        $z = $v[$n-1];

    }
    return pack( "V$n", @v );
}

sub xxtea_decrypt {
    my ($s, $k) = @_;
    if ($s eq "") {
        return "";
    }
    my @v = _str2long($s, 0);
    my @k = _str2long($k, 0);
    if (@k < 4) {
        for (my $i = @k; $i < 4; $i++) {
                $k[$i] = 0;
        }
    }
    my $y = $v[0];
    my $n = @v;
    die "n = $n\n" if $n < 2;
    my $z = $v[$n-1];
    use integer;
    my $q = 6 + 52 / $n;
    no integer;
    my $delta = 0x9E3779B9;
    my $sum = ($q * $delta) % 4294967296;
    my $e = 0;
    my $p = 0;
    my $mx = 0;
    while ($sum != 0) {

        $e = $sum >> 2 & 3;
        for ($p = $n-1; $p > 0; $p--) {
            $z = $v[$p - 1];
            $mx = (((($z>>5^$y<<2) % 4294967296) + (($y>>3^$z<<4) % 4294967296)) % 4294967296) ^ ((($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z)) % 4294967296); 
            $v[$p] = ($v[$p] - $mx) % 4294967296;
            $y = $v[$p];

        }
        $z = $v[$n-1];
        $mx = (((($z>>5^$y<<2) % 4294967296) + (($y>>3^$z<<4) % 4294967296)) % 4294967296) ^ ((($sum ^ $y) + ($k[$p & 3 ^ $e] ^ $z)) % 4294967296); 
        $v[0] = ($v[0] - $mx) % 4294967296;
        $y = $v[0];
        $sum = ($sum - $delta) % 4294967296;

    }
    return pack( "V*", @v );

}

1;

__END__

=head1 NAME

Crypt::XXTEA - XXTEA encryption arithmetic module.

=head1 SYNOPSIS

    use Crypt::XXTEA;

=head1 DESCRIPTION

XXTEA is a secure and fast encryption algorithm. It's suitable for web
development. This module allows you to encrypt or decrypt a string using
the algorithm. 

=head1 FUNCTIONS

=over 4

=item xxtea_encrypt

    my $ciphertext = xxtea_encrypt($plaintext, $key);

This function encrypts $plaintext using $key and returns the $ciphertext.

=item encrypt

    my $ciphertext = Crypt::XXTEA::encrypt($plaintext, $key);
   
This function is the same as xxtea_encrypt.

=item xxtea_decrypt

    my $plaintext = xxtea_decrypt($ciphertext, $key);

This function decrypts $ciphertext using $key and returns the $plaintext.

=item decrypt

    my $plaintext = Crypt::XXTEA::decrypt($ciphertext, $key);

This function is the same as xxtea_decrypt.

=back

=head1 EXAMPLE

    use Crypt::XXTEA;
    my $ciphertext = xxtea_encrypt("Hello XXTEA.", "1234567890abcdef");
    my $plaintext = xxtea_decrypt($ciphertext, "1234567890abcdef");
    print $plaintext;

    $ciphertext = Crypt::XXTEA::encrypt("Hi XXTEA.", "1234567890abcdef");
    $plaintext = Crypt::XXTEA::decrypt($ciphertext, "1234567890abcdef");
    print $plaintext;

=head1 NOTES

If $plaintext is equal to "", it returns "".

It returns 0 when fails to decrypt.

Only the first 16 bytes of $key is used. if $key is shorter than 16 bytes,
it will be padding \0.

The XXTEA algorithm is stronger and faster than Crypt::DES, Crypt::Blowfish
& Crypt::IDEA.

=head1 SEE ALSO

Crypt::DES
Crypt::Blowfish
Crypt::IDEA

=head1 COPYRIGHT

The implementation of the XXTEA algorithm was developed by,
and is copyright of, Ma Bingyao (andot@ujn.edu.cn).

Module completely reworked and packaged by 
Brian Kurle <bk@travelingbits.com>

=cut
