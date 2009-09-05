#!perl -T

use Test::More;
use Crypt::XXTEA;

my  @tests;
my  $blockType;
my  $blockTest = 1;

{
    # Read in the data block (fetched from http://www.crypt.co.za/post/27)
    local $/ = "\n";
    @tests = <DATA>;

}

# Determine number of tests (take number of lines read and subtract comment lines)
plan( tests => 2 * ( scalar @tests - scalar grep /^#/, @tests ) );

foreach my $test ( @tests ) {

    chomp $test;

    # See if line read is a comment line
    if( $test =~ /^#\s*(.*)/ ) {
        $blockType = $1 . ": "; # Set comment for test
        $blockTest = 1;         # Reset count for this block type
        next;                   # Skip to next line

    }

    $test =~ s/\s*//g;           # kill embedded spaces

    my  ($key, $plaintext, $ciphertext) = split /,/, $test; # fetch results
    my  ($binkey, $binplaintext, $binciphertext) = map { pack "H*", $_ } ($key, $plaintext, $ciphertext);

    # xxtea_encrypt and xxtea_decrypt return binary values... I really don't want
    # the Harness to attempt to print out the binary when it fails and muck up
    # the TTY.  So, convert the binary back to ascii and compare that.  Same
    # affect with the benefit that when it fails, it prints out pretty, too.

    is( unpack( "H*", xxtea_encrypt( $binplaintext, $binkey ) ), $ciphertext, "$blockType$blockTest (encryption)" );
    is( unpack( "H*", xxtea_decrypt( $binciphertext, $binkey ) ), $plaintext, "$blockType$blockTest (decryption)" );
    $blockTest++;

}


#diag( "Testing Crypt::XXTEA $Crypt::XXTEA::VERSION, Perl $], $^X" );
__DATA__
# 64-bit block
00000000000000000000000000000000, 0000000000000000, ab043705808c5d57
0102040810204080fffefcf8f0e0c080, 0000000000000000, d1e78be2c746728a
9e3779b99b9773e9b979379e6b695156, ffffffffffffffff, 67ed0ea8e8973fc5
0102040810204080fffefcf8f0e0c080, fffefcf8f0e0c080, 8c3707c01c7fccc4
# 96-bit block
ffffffffffffffffffffffffffffffff, 157c13a850ba5e57306d7791, b2601cefb078b772abccba6a
9e3779b99b9773e9b979379e6b695156, 157c13a850ba5e57306d7791, 579016d143ed6247ac6710dd
# 128-bit block
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, 0102040810204080fffefcf8f0e0c080, c0a19f06ebb0d63925aa27f74cc6b2d0
9e3779b99b9773e9b979379e6b695156, 0102040810204080fffefcf8f0e0c080, 01b815fd2e4894d13555da434c9d868a
# 160-bit block
0102040810204080fffefcf8f0e0c080, 157c13a850ba5e57306d77916fa2c37be1949616, 51f0ffeb46012a245e0c6c4fa097db27caec698d
# 192-bit block
9e3779b99b9773e9b979379e6b695156, 690342f45054a708c475c91db77761bc01b815fd2e4894d1, 759e5b212ee58be734d610248e1daa1c9d0647d428b4f95a
# 224-bit block
9e3779b99b9773e9b979379e6b695156, 3555da434c9d868a1431e73e73372fc0688e09ce11d00b6fd936a764, 8e63ae7d8a119566990eb756f16abf94ff87359803ca12fbaa03fdfb
# 256-bit block
0102040810204080fffefcf8f0e0c080, db9af3c96e36a30c643c6e97f4d75b7a4b51a40e9d8759e581e3c40b341b4436, 5ef1b6e010a2227ba337374b59beffc5263503054745fb513000641e2c7dd107
# 8-bit message, zero-padded to 64-bit
6a6f686e636b656e64616c6c6a6f686e, 4100000000000000, 014e7a34874eeb29
# 16-bit message, zero-padded to 64-bit
6a6f686e636b656e64616c6c6a6f686e, 4142000000000000, e9d39f636e9ed090
# 24-bit message, zero-padded to 64-bit
6a6f686e636b656e64616c6c6a6f686e, 4142430000000000, d20ec51c06feaf0e
# 32-bit message, zero-padded to 64-bit
6a6f686e636b656e64616c6c6a6f686e, 4142434400000000, b1551d6ffcd4b61b
# 40-bit message, zero-padded to 64-bit
6a6f686e636b656e64616c6c6a6f686e, 4142434445000000, 0ff91e518b9837e3
# 48-bit message, zero-padded to 64-bit
6a6f686e636b656e64616c6c6a6f686e, 4142434445460000, 7003fc98b6788a77
# 56-bit message, zero-padded to 64-bit
6a6f686e636b656e64616c6c6a6f686e, 4142434445464700, 93951ad360650022
# 64-bit message
6a6f686e636b656e64616c6c6a6f686e, 4142434445464748, cdeb72b9c903ce52
