/*
-----------------------------------------------------------------
Header file for Maraca, a submission for the SHA-3 hash.  Maraca
runs in about 5 cycles per byte and produces a 1024 bit hash.

This implementation assumes a little-endian platform and that
"unsigned long long" is an 8-byte quantity.  

The internal state stores 47 128-byte accumulators as well as a 
128-byte key and 128-byte state, taking up 6680 bytes total.
-----------------------------------------------------------------
*/

#include <emmintrin.h>

typedef unsigned char BitSequence;      /* 1 byte unsigned */
typedef unsigned long long DataLength;  /* a big type for holding lengths */

typedef enum 
{ 
  SUCCESS = 0, 
  FAIL = 1, 
  BAD_HASHBITLEN = 2, 
  BAD_KEYBITLEN = 3,
  BAD_PREVIOUS_DATABITLEN = 4,
  BAD_STATE = 5
} 
HashReturn;

#define MARACA_LEN     8     /* number of 16-byte values per block */

#define MARACA_BLOCKS  64    /* array of pointers to accumulators */
#define MARACA_ACCUM   47    /* actual accumulators */

typedef  struct hashState {
  __m128i hash[MARACA_LEN];  /* the internal state */
  __m128i key[MARACA_LEN];   /* the key */
  __m128i buf[MARACA_LEN];   /* an aligned block of data */
  __m128i abuf[MARACA_ACCUM][MARACA_LEN]; /* accumulator buffers */
  __m128i *a[MARACA_BLOCKS]; /* accumulators */
  DataLength length;    /* total length hashed */
  int    running;       /* may Update() or Final() be called? */
  int    hashbitlen;    /* length of hash value, in bits */
  int    keybitlen;     /* length of key, in bits (multiple of 128) */
  DataLength offset;    /* offset into the accumulators */
} hashState;

/* Initialize a state with a key so that Update and Final can be called */
HashReturn InitWithKey( hashState *state,
			int hashbitlen, 
			const BitSequence *key,
			int keybitlen);


/* Initialize a state so that Update and Final can be called */
HashReturn Init( hashState *state,
		 int hashbitlen);

/* Update the state with a byte array full of data */
/* This can be called many times, but all but the last need databitlen%8==0 */
HashReturn Update( hashState *state, 
		   const BitSequence *data, 
		   DataLength databitlen);

/* wrap up the hash and report the result */
HashReturn Final( hashState *state, 
		  BitSequence *hashval);

/* hash a byte array of data */
HashReturn Hash( int hashbitlen,          /* length of hashval, in bits */
		 const BitSequence *data, /* array of bytes to hash */
		 DataLength databitlen,   /* length of the data, in bits */
		 BitSequence *hashval);   /* 128-byte hash value */



