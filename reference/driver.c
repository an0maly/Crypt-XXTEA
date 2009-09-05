#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//#define DEBUG
#define usage()     fprintf( stderr, "usage: xxtea encode <key> <plaintext>\n" \
		                             "usage: xxtea decode <key> <ciphertext>\n" \
                                     "\n" \
                                     "Both key, plaintext/ciphertext parameters are assumed to be a string\n" \
                                     "of hexadecimal digit representing the binary blocks\n" )

long btea( uint32_t* v, int32_t n, uint32_t* k );
size_t pack( char *ascii, uint8_t *p );
 
int
main( int ac, char *av[] ) 
{
	uint8_t *v = NULL;
	uint8_t *k = NULL;
	int32_t	n = 0;
	size_t	textlen = 0;
	char	*text = av[3];
	size_t	keylen = 0;
	char	*key = av[2];
	long	rc = 0L;
	short	i;
	uint8_t *p;

	if( ac < 4 ) {
        usage();
		return 0;

	}

	keylen = strlen( key ) / 2;
	assert( keylen );

	k = calloc( 1, keylen );
	assert( k );

	textlen = strlen( text ) / 2;
	assert( textlen );

	v = calloc( 1, textlen );
	assert( v );

	n = textlen / sizeof( uint32_t );

    if( strcmp( av[1], "encode" ) == 0 ) 
        ;
    else if( strcmp( av[1], "decode" ) == 0 )
        n = -n;
    else {
        usage();
        return 0;

    }

	pack( key, k );
	pack( text, v );

#ifdef DEBUG
	for( i = 0, p = k; i < keylen; i++ )
		printf( "%02x", *p++ );

	printf( ", " );

	for( i = 0, p = v; i < textlen; i++ )
		printf( "%02x", *p++ );

	printf( ", " );
#endif

	rc = btea( (uint32_t *)v, n, (uint32_t *)k );

	for( i = 0, p = v; i < textlen; i++ )
		printf( "%02x", *p++ );
	
	printf( "\n" );
	
	return 0;
}

size_t
pack( char *ascii, uint8_t *p )
{
	size_t	len = 0;
	size_t	bytes = 0;
	uint8_t	byte = 0;
	char	*str = ascii;
	int		push = 0;

	assert( ascii );
	assert( p );

	len = strlen( ascii );
	bytes = len / 2;

	if( len % 2 ) {
		fprintf( stderr, "String does not have an even number of nibbles (encountered %lu nibbles)\n%s\n",
			len, ascii );

		return 0;

	}

	while( *str ) {								// look for null at end of string
		if( isdigit( *str ) )					// have we a digit?
			byte |= *str - '0';					// convert to nibble
		else if( *str >= 'A' && *str <= 'F' )	// upper case hex character?
			byte |= (*str - 'A') + 10;
		else if( *str >= 'a' && *str <= 'f' )	// lower case hex character?
			byte |= (*str - 'a') + 10;
		else {
			fprintf( stderr, "String contains an invalid hexadecimal character (encountered %c)\n%s\n",
				*str, ascii );

			return 0;

		}
		if( push++ ) {							// have we processed a complete byte's worth?
			*p++ = byte;						// store it and move along
			byte = push = 0;					// reset byte

		}
		else
			byte <<= 4;
		str++;

	}

	return bytes;

}
		

