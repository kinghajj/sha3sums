/*\
\ / Unrolled EnRUPT hash implementing irRUPT32-224, irRUPT32-256, irRUPT64-384 and irRUPT64-512 stream hashing modes of operation for P=2 and s=4
/ \ Designed and implemented by Sean O'Neil
\ / NIST SHA-3 submission by VEST Corporation
/ \ Released to the public domain by the author on November 1, 2008.
\*/

#ifndef _EnRUPT_h_
#define _EnRUPT_h_

#include "../portEnRUPT.h"

typedef u8					BitSequence;
typedef size_t				DataLength;	/* the largest integer type supported by the environment */
typedef enum _HashReturn
{
	SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2
} HashReturn;

typedef HashReturn iru (void * state, const BitSequence * data, const DataLength databitlen);
typedef HashReturn irf (void * state, BitSequence * hashval);

typedef struct _hashState
{
#if defined(_MSC_VER)||defined(__INTEL_COMPILER)
	__declspec(align(16))
#endif
	u8						x[160]	/* H<=16, two d accumulators and two last r indexes (it's okay if they roll over 2^W) */
#ifdef __GNUC__
	__attribute__ ((aligned (16)))
#endif
	;
	u8						p[80];	/* maximum 8-word input block with two spare words for the padding */
	int						n;		/* bits in the input block */
	int						hashbitlen; /* hash output size in bits */
	iru						*u;		/* hash update function optimized for that size */
	irf						*f;		/* hash finale function optimized for that size */
} hashState
;

HashReturn Init (hashState *state, int hashbitlen);
HashReturn Update (hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Final (hashState *state, BitSequence *hashval);
HashReturn Hash (int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

#endif
