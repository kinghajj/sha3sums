/*\
\ / Reference implementation of EnRUPT32 and EnRUPT64 in irRUPT stream hashing mode of operation
/ \ Designed and implemented by Sean O'Neil
\ / NIST SHA-3 submission by VEST Corporation
/ \ Released to the public domain by the author on November 1, 2008.
\*/

#include <string.h>
#include "SHA3api_ref.h"

/* Single irreversible EnRUPT (ir1) round for any P and any w */

#define ir1(x,d,r,H,P,w) (x[(r+P)%H]^=f=rotr(2*x[(r/P*P+(r+1)%P)%H]^x[(r+2*P)%H]^d[r%P]^r,w/4)*9, d[r%P]^=f^x[(H*P/2+P%2+r++)%H])

static void EnRUPT2s (hashState *state, const uw p)
{
	uw					i, f;
	
	for (i = 0; i < 2*_ER_s_; i++)
	{
		ir1 (state->x, state->d, state->r, state->H, _ER_P_, _ER_w_);
	}
	state->d[_ER_P_-1] ^= p;
}

HashReturn Init (hashState *state, int hashbitlen)				/* once per message API initialization */
{
	if ((hashbitlen < 2*_ER_w_) || (hashbitlen > 8*(_ER_s_-1)*_ER_w_))
	{
		state->n = -1;											/* no entry to Update or Final */
		return BAD_HASHBITLEN;									/* this implementation cannot handle fewer than 6 words in the state */
	}
	memset (state->x, 0, sizeof (hashState));
	state->hashbitlen = hashbitlen;
	state->H = (hashbitlen*2+_ER_w_*_ER_P_-1)/_ER_w_/_ER_P_*_ER_P_;	/* 4 to 16*(s-1) words in the state */
	return SUCCESS;
}

HashReturn Update (hashState *state, const BitSequence *data, DataLength databitlen)
{
	size_t				i = _ER_w_-state->n;
	
	if (state->n&7) return FAIL;								/* unaligned bitwise hashing is not supported */
	if (databitlen < i)											/* not enough to fill up one word */
	{
		memcpy (((u8*)&state->p) + (state->n>>3), data, (databitlen+7)>>3);
		state->n += (int) databitlen;
		return SUCCESS;											/* nothing to process yet */
	}
	if (state->n)												/* any leftovers? */
	{
		memcpy (((u8*)&state->p) + (state->n>>3), data, i>>3);
		EnRUPT2s (state, in_word(state->p));					/* processing the accumulated data first */
		databitlen -= i;
		state->n = 0;
	}
	else i = 0;													/* otherwise start with the first byte */
	for (; databitlen >= _ER_w_; databitlen -= _ER_w_, i += _ER_w_)
	{
		EnRUPT2s (state, in_word(*(uw *)(data+(i>>3))));		/* hashing the input word by word */
	}
	if (databitlen)
	{
		memcpy (&state->p, data+(i>>3), (databitlen+7)>>3);
		state->n = (int) databitlen;							/* saving the remaining appendix */
	}
	return SUCCESS;
}

HashReturn Final (hashState *state, BitSequence *hashval)
{
	register int		i = state->n>>3, j = ((state->n&7)^7);
	uw					o;
	
	if (state->n < 0) return FAIL;								/* and don't you come back no more! */
	((u8*)(&state->p))[i] &= -1 << j;							/* masking off possible garbage */
	((u8*)(&state->p))[i] |=  1 << j;							/* adding the padding bit */
	EnRUPT2s (state, in_word(state->p));						/* hashing in the last remaining bits, padded */
	EnRUPT2s (state, state->hashbitlen);						/* hashing in the hash length in bits */
	for (i = 0; i < state->H; i++)
	{
		EnRUPT2s (state, 0);									/* sealing the state */
	}
	for (i = 0; i < state->hashbitlen/_ER_w_; i++)
	{
		EnRUPT2s (state, 0);
		((uw*)hashval)[i] = out_word (state->d);				/* returning the hash value word by word */
	}
	if (state->hashbitlen % _ER_w_)								/* odd hash length, why not? */
	{
		EnRUPT2s (state, 0);
		o = out_word (state->d);
		memcpy (hashval+i*_ER_w_/8, &o, (((size_t)state->hashbitlen%_ER_w_)+7)>>3);
	}
	state->n = -1;												/* Hit the road, Jack! */
	return SUCCESS;
}

HashReturn Hash (int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	hashState			state;
	HashReturn			i = Init (&state, hashbitlen);
	
	if (i != SUCCESS) return i;									/* BAD_HASHBITLEN */
	Update (&state, data, databitlen);
	return Final (&state, hashval);								/* Init-Update-Final single call hashing */
}
