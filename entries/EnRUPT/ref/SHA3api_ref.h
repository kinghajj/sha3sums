/*\
\ / Reference implementation of EnRUPT32 and EnRUPT64 in irRUPT stream hashing mode of operation
/ \ Designed and implemented by Sean O'Neil
\ / NIST SHA-3 submission by VEST Corporation
/ \ Released to the public domain by the author on November 1, 2008.
\ /
/ \ #define _ER_w_ 32 for EnRUPT32
\ / #define _ER_w_ 64 for EnRUPT64, proposed for SHA-3
/ \
\ / #define _ER_P_ 1 for the simplest variant, no parallelisation
/ \ #define _ER_P_ 2 for the default (recommended) 2x parallelisable EnRUPT
\ / #define _ER_P_ 4 for the maximum advised 4x parallelisation
/ \ #define _ER_P_ 8 or greater or other odd values for research purposes
\ /
/ \ #define _ER_s_ 1 for non-cryptographic hashing and MACs; minimum hash size = 2*_w_ for any _s_
\ / #define _ER_s_ 2 for indistinguishability from random; maximum hash size = 8*_w_
/ \ #define _ER_s_ 3 for resistance to non-adaptive attacks; maximum hash size = 16*_w_
\ / #define _ER_s_ 4 for resistance to adaptive attacks; maximum hash size = 24*_w_
/ \ #define _ER_s_ 5 or greater for higher security; maximum hash size = 8*(_s_-1)*_w_
\*/

#ifndef _EnRUPT_h_
#define _EnRUPT_h_

#include "../portEnRUPT.h"

#define _ER_w_				64					/* Word size in bits, w=32 or w=64 */
#define _ER_P_				2					/* 2x parallelisable variant, 1<=P<=4 */
#define _ER_s_				4					/* Security parameter, 1<=s, default s=4 */

#if (_ER_w_>32)
	#define rotr			rotr64				/* only rotation right is needed */
	#define uw				u64					/* unsigned 64-bit word type for the state */
	#define bswap			bswap64				/* only needed for little-endian architectures */
#else
	#define rotr			rotr32				/* only rotation right is needed */
	#define uw				u32					/* unsigned 32-bit word type for the state */
	#define bswap			bswap32				/* only needed for little-endian architectures */
#endif

#if defined(ENRUPT_1234_BYTE_ORDER)
	#define in_word(p)		bswap(p)
	#define out_word(d)		bswap(d[_ER_P_-1])
#elif defined(ENRUPT_4321_BYTE_ORDER)
	#define in_word(p)		p
	#define out_word(d)		d[_ER_P_-1]
#else
	#error Unknown endianness. Please define.
#endif

typedef u8					BitSequence;
typedef size_t				DataLength;			/* the largest integer type supported by the environment */
typedef enum _HashReturn
{
	SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2
} HashReturn;
typedef struct _hashState
{
	uw						x[16*(_ER_s_-1)];	/* internal state of the hash, up to 48 words for s=4 */
	uw						d[_ER_P_];			/* P delta accumulators */
	uw						r;					/* current round number (it's okay if it rolls over 2^w) */
	uw						p;					/* plaintext input word */
	uw						hashbitlen;			/* hash output size in bits */
	int						n;					/* bits remaining in the input word p */
	int						H;					/* number of words in the internal state x */
} hashState;

HashReturn Init (hashState *state, int hashbitlen);
HashReturn Update (hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Final (hashState *state, BitSequence *hashval);
HashReturn Hash (int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

#endif
