#include <stdlib.h>
#include <stdint.h>

#define DELTA 0x9e3779b9UL
#define MX ((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z))

long btea(uint32_t* v, int32_t n, uint32_t* k) 
{
	uint32_t z, y=v[0], sum=0, e;
	uint32_t p, q;
	uint32_t mx;

	if (n > 1) {          /* Coding Part */
		z=v[n-1];
		q = 6 + 52/n;

		while (q-- > 0) {
			sum += DELTA;
			e = (sum >> 2) & 3;
			for (p=0; p<n-1; p++) {
				y = v[p+1]; 

				mx = (z>>5^y<<2);
				mx = (y>>3^z<<4);
				mx = ((z>>5^y<<2) + (y>>3^z<<4));
				mx = (sum^y);
				mx = (k[(p&3)^e] ^ z);
				mx = ((sum^y) + (k[(p&3)^e] ^ z));
				mx = ((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z));

				z = v[p] += MX;
			}
			y = v[0];

			mx = (z>>5^y<<2);
			mx = (y>>3^z<<4);
			mx = ((z>>5^y<<2) + (y>>3^z<<4));
			mx = (sum^y);
			mx = (k[(p&3)^e] ^ z);
			mx = ((sum^y) + (k[(p&3)^e] ^ z));
			mx = ((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z));

			z = v[n-1] += MX;

		}
		return 0 ; 

	} else if (n < -1) {  /* Decoding Part */
		n = -n;
		z=v[n-1];
		q = 6 + 52/n;
		sum = q*DELTA ;
		while (sum != 0) {
			e = (sum >> 2) & 3;
			for (p=n-1; p>0; p--) {
                z = v[p-1]; 

				mx = (z>>5^y<<2);
				mx = (y>>3^z<<4);
				mx = ((z>>5^y<<2) + (y>>3^z<<4));
				mx = (sum^y);
				mx = (k[(p&3)^e] ^ z);
				mx = ((sum^y) + (k[(p&3)^e] ^ z));
				mx = ((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z));

                y = v[p] -= MX;

            }
			z = v[n-1];

            mx = (z>>5^y<<2);
            mx = (y>>3^z<<4);
            mx = ((z>>5^y<<2) + (y>>3^z<<4));
            mx = (sum^y);
            mx = (k[(p&3)^e] ^ z);
            mx = ((sum^y) + (k[(p&3)^e] ^ z));
            mx = ((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z));

			y = v[0] -= MX;
			sum -= DELTA;

		}
		return 0;

	}
	return 1;

}
