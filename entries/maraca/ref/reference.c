/*
-----------------------------------------------------------------
Software implementation of Maraca, a submission for the NIST SHA-3 
cryptographic hash competition.  Reference version.

Bits are arranged in an 8x8 grid of 16-bit chunks.  A 1024-bit 
permutation (a call to perm()) consists of applying a 16-bit 
permutation to each chunk, then rotating each of the 16 bit 
positions by different amounts through the 64 chunks.  The rotates 
are chosen so all shift amounts up and left in the grid are used 
by some two bits.

The nonlinear mix of 16-bit chunks is actually an 8-bit permutation 
applied to the even bits and again to the odd bits, with the 16 bits 
shuffled at the end.  This is 5 NAND gates deep.  6 of the 16 bits
look like a^b^c^d, and can be inverted and still be implemented 5 
NAND gates deep.  Symmetry is broken by inverting different subsets
of these 6 bits in each of the 64 chunks.  Symmetry breaking is done
in software by XORing constants.  The 16-bit permutation has avalanche
of 0.375 when applied to itself three times.

It takes 8 perms forward or 7 perms backwards for all bits to be 
affected by all one-bit deltas for nearly-zero states (avalanche 
0.27 forward, 0.23 backward).  For random base states, 7 perms 
forward has avalanche 0.378, 6 backwards has avalanche 0.19.  Deltas
of two bits on random bases also do avalanche in 7 perms forward 
or 6 perms back.

Maraca makes the ungrounded assumption that twice forward + backward
avalanche, 30 perms that is, is enough to thwart cryptanalysis.
Further, it assumes it doesn't matter if these are consecutive perms
or how many blocks are involved.  This is done with 3-perm rounds.
Each block is combined four times, in rounds i, i+21-6(i%4), 
i+41-6((i+2)%4), and i+46.  The first use is offset by one perm from 
where the other uses of other blocks are combined.  This
guarantees deltas must pass through at least one new perm per 
delta-containing block.  Brute-force search suggests there is no delta 
that requires passing through less than 30 perms.

(by Bob Jenkins, August 22 2008, public domain)
-----------------------------------------------------------------
*/

#include <stdio.h>
#include <stddef.h>
#include "SHA3api_ref.h"

#define BYTES_PER_BLOCK (sizeof(u8)*MARACA_LEN)
#define BITS_PER_BLOCK  (8*BYTES_PER_BLOCK)
#define bytes(x)        (((x)+7)/8)

/* #define TRACE_INTERMEDIATE_VALUES */


/* eight: apply the 8-bit permutation to the even bits */

#define xor( a, b)  (a ^ b)
#define or( a, b)  (a | b)
#define and( a, b)  (a & b)
#define ant( a, b)  (~a & b)
#define not(a)  ~a
#define read( x, i)  x[i*2]
#define write( y, i, a)  y[i*2] = a

static void eight( u8 *x, u8 *y)
{
  u8 q,r;
  u8 a0 = read( x, 0);
  u8 a1 = read( x, 1);
  u8 a2 = read( x, 2);
  u8 a3 = read( x, 3);
  u8 a4 = read( x, 4);
  u8 a5 = read( x, 5);
  u8 a6 = read( x, 6);
  u8 a7 = read( x, 7);

  q = xor(a4,a5);
  r = xor(a7,a0);
  write(y,0,xor(q,r));

  q = xor(a5,a1);
  r = xor(a3,a2);
  write(y,1,xor(q,r));

  q = xor(a3,a4);
  r = xor(a5,a1);
  write(y,2,xor(q,r));

  q = ant(xor(a0,a3),xor(a6,a4));
  r = ant(xor(a4,a6),or(and(a0,a1),ant(a0,a3)));
  write(y,3,or(q,r));

  q = ant(xor(a6,a7),xor(a5,a2));
  r = and(or(not(or(a2,a5)),and(a4,a5)),xor(a7,a6));
  write(y,4,or(q,r));

  q = and(xor(a5,a0),xor(a4,a2));
  r = ant(xor(a2,a4),or(and(a0,a5),ant(a0,a1)));
  write(y,5,or(q,r));

  q = and(xor(a4,a2),xor(a7,a6));
  r = ant(xor(a2,a4),or(ant(a7,a0),and(a6,a7)));
  write(y,6,or(q,r));

  q = and(or(not(or(a6,a7)),ant(and(a6,a7),a0)),xor(a4,a2));
  r = ant(xor(a2,a4),or(ant(and(a0,a2),a6),ant(a0,a7)));
  write(y,7,or(q,r));

}


#ifdef TRACE_INTERMEDIATE_VALUES
static int display_count;
#endif


/* perm: one 1024-bit permutation */

static int shift[MARACA_LEN] = {40,60,26,4,0,3,11,15,13,13,1,41,14,7,18,14};
static int map[MARACA_LEN] = {12,13,4,9,1,14,5,2,10,8,6,7,3,15,0,11};

static void perm(u8 *x)
{
  int i;
  u8 y[MARACA_LEN];

#ifdef TRACE_INTERMEDIATE_VALUES
  printf("Before permutation %d\n", display_count);
  for (i=0; i<MARACA_LEN; ++i)
  {
    printf("%.16llx ", x[i]);
    if ((i%4) == 3) printf("\n");
  }
  printf("\n");
#endif /* TRACE_INTERMEIDATE_VALUES */

  /* do 128 8-bit permutations */
  eight( x, y);           /* the eight even bits */
  eight( &x[1], &y[1]);   /* the eight odd bits */

  /* break symmetry among the 64 16-bit permutations */
  y[0] ^= 0x18f8aa72369b75c2LL;
  y[1] ^= 0x337b824aab77201fLL;
  y[2] ^= 0x60bd51315e37b49cLL;
  y[3] ^= 0x82ed31eb138e02efLL;
  y[4] ^= 0x5fe101ed66fc3130LL;
  y[5] ^= 0x1019906dca58dffbLL;

  /* rotate the output bits among the 64 chunks */
  for (i=0; i<MARACA_LEN; ++i) 
  {
    y[i] = (y[i] << shift[i]) | (y[i] >> (64-shift[i]));
  }

  /* shuffle the 16 output bits within each chunk */
  for (i=0; i<MARACA_LEN; ++i) 
  {
    x[map[i]] = y[i];
  }

#ifdef TRACE_INTERMEDIATE_VALUES
  printf("After permutation %d\n", display_count++);
  for (i=0; i<MARACA_LEN; ++i)
  {
    printf("%.16llx ", x[i]);
    if ((i%4) == 3) printf("\n");
  }
  printf("\n");
#endif /* TRACE_INTERMEIDATE_VALUES */
}



/* The full hash */


/* do_combine: combine an accumulator with the state */
static void do_combine( const u8 *accum, u8 *state)
{
  int i;

#ifdef TRACE_INTERMEDIATE_VALUES
  printf("Combining data block\n");
  for (i=0; i<MARACA_LEN; ++i)
  {
    printf("%.16llx ", ((u8 *)accum)[i]);
    if ((i%4) == 3) printf("\n");
  }
  printf("\n");
#endif /* TRACE_INTERMEIDATE_VALUES */

  for (i=0; i<MARACA_LEN; ++i) 
  {
    state[i] ^= accum[i];
  }
}


/* accumulate: add a block to its second, third, fourth accumulators */
#define SECOND 21
#define THIRD  41
#define FOURTH 46
void accumulate( u8 **a, const u8 *next, int x)
{
  u8 *fourth = a[(x + FOURTH) % MARACA_BLOCKS];
  u8 *third  = a[(x + THIRD - 6*((x+2)%4)) % MARACA_BLOCKS];
  u8 *second = a[(x + SECOND - 6*(x%4)) % MARACA_BLOCKS];
  a[(x + MARACA_ACCUM) % MARACA_BLOCKS] = a[x % MARACA_BLOCKS];
  int i;
  
  for (i=0; i<MARACA_LEN; ++i) 
  {
    u8 val = next[i];
    fourth[(i+12) % MARACA_LEN]  = val;
    third [(i+ 6) % MARACA_LEN] ^= val;
    second[(i+ 2) % MARACA_LEN] ^= val;
  }
}



/* one combine: add a data block, perm, and an accumulator, perm perm */
static void one_combine( u8 **a, DataLength *index, u8 *state, const u8 *next)
{
  accumulate( a, next, *index);
  do_combine( next, state);
  perm( state);
  do_combine( a[*index % MARACA_BLOCKS], state);
  perm( state);
  perm( state);
  ++*index;
}



/* Init: initialize the hash */
HashReturn Init( hashState *state,
		 int hashbitlen) 
{
  int i;

#ifdef TRACE_INTERMEDIATE_VALUES
  display_count = 0;
#endif

  if (hashbitlen > BITS_PER_BLOCK || (hashbitlen % 8) != 0) 
  {
    return BAD_HASHBITLEN;
  }

  state->hashbitlen = hashbitlen;
  state->keybitlen = 0;
  state->offset = 0;
  state->length = 0;
  memset( state->hash, 0, BYTES_PER_BLOCK);
  memset( state->key, 0, BYTES_PER_BLOCK);
  memset( state->abuf, 0, sizeof(state->abuf));
  for (i=0; i<MARACA_ACCUM; ++i) 
  {
    state->a[i] = state->abuf[i];
  }
  state->running = 1;
  return SUCCESS;
}




/* Update: update the hash with a bit array */
/* Update must follow an Init or another Update */
HashReturn Update( hashState *state, 
		   const BitSequence *data, 
		   DataLength databitlen)
{
  unsigned int start = state->length % BITS_PER_BLOCK;
  size_t stop;
  size_t dataoff = 0;

  if (!state->running) 
  {
    return BAD_STATE;
  }

  if ((start % 8) != 0)
  {
    return BAD_PREVIOUS_DATABITLEN;
  }

  /* get started */
  state->length += databitlen;
  if (start != 0) 
  {
    if (databitlen + start < BITS_PER_BLOCK) 
    {
      memcpy( &((char *)state->buf)[bytes(start)], data, bytes(databitlen));
      return;
    }
    else
    {
      unsigned int piece = (BITS_PER_BLOCK-start)/8;
      memcpy( &((char *)state->buf)[bytes(start)], data, piece);
      one_combine( state->a, &state->offset, state->hash, state->buf);
      data = &data[piece];
      databitlen -= piece;
    }
  }

  /* loop: handle a whole block at a time */
  stop = (databitlen / BITS_PER_BLOCK) * BYTES_PER_BLOCK;
  for (dataoff = 0; dataoff < stop; dataoff += BYTES_PER_BLOCK)
  {
    memcpy( state->buf, &((char *)data)[dataoff], BYTES_PER_BLOCK);
    one_combine( state->a, &state->offset, state->hash, state->buf);
  }

  /* remember the last partial block */
  memcpy( state->buf, &((char *)data)[stop], bytes(databitlen) - stop);

  return SUCCESS;
}




/* InitWithKey: initialize the hash with a key */
HashReturn InitWithKey( hashState *state,
			int hashbitlen, 
			const BitSequence *key,
			int keybitlen)
{
  if (keybitlen > BITS_PER_BLOCK || (keybitlen % 128) != 0)
  {
    return BAD_KEYBITLEN;
  }
  if (Init( state, hashbitlen)) return FAIL;
  state->keybitlen = keybitlen;
  memcpy(state->key, key, bytes(keybitlen));
  if (Update( state, (const BitSequence *)state->key, keybitlen)) return FAIL;
  return SUCCESS;
}



/* Final: hash the last piece, the key and length, then report the result */
HashReturn Final( hashState *state, 
		  BitSequence *hashval)
{
  int i;
  int fraction = -state->length % 8;
  int pad = 0;
  unsigned short int lengths;  /* a 2-byte unsigned integer */

  if (!state->running) 
  {
    return BAD_STATE;
  }

  /* pad the last partial block to a 1-byte boundary */
  if (fraction != 0)
  {
    int last = (state->length % BITS_PER_BLOCK)/8;

    /* clear the unused bits of the last used byte */
    ((char *)state->buf)[last] &= ~(char)((1 << fraction) - 1);
    state->length += fraction;

    if (last == BYTES_PER_BLOCK-1)
    {
      one_combine( state->a, &state->offset, state->hash, state->buf);
    }
  }

  /* Update with the key again */
  if (state->keybitlen != 0)
  {
    Update( state, (BitSequence *)state->key, state->keybitlen);
  }

  /* Update with the keybitlen and zero-padded fraction length, and a 1 */
  lengths = 16*state->keybitlen + 2*fraction + 1;     
  Update( state, (BitSequence *)&lengths, 16);

  /* finish padding the last partial block */
  pad = (-state->length % BITS_PER_BLOCK)/8;
  if (pad != 0)
  {
    memset( &((char *)state->buf)[BYTES_PER_BLOCK-pad], 0, pad);
    one_combine( state->a, &state->offset, state->hash, state->buf);
  }

  /* use up the accumulators */
  perm( state->hash);
  for (i=0; i<FOURTH-1; ++i)
  {
    do_combine( state->a[state->offset % MARACA_BLOCKS], state->hash);
    perm( state->hash);
    perm( state->hash);
    perm( state->hash);
    ++state->offset;
  }

  /* the last combine: no mixing needed after this */
  do_combine( state->a[state->offset % MARACA_BLOCKS], state->hash);

  /* report the final state */
  memcpy( hashval, state->hash, bytes(state->hashbitlen));

  state->running = 0;
  return SUCCESS;
}




HashReturn Hash( int hashbitlen,          /* length of hashval, in bits */
		 const BitSequence *data, /* array of bytes to hash */
		 DataLength databitlen,   /* length of the data, in bits */
		 BitSequence *hashval)    /* 128-byte hash value */
{
  hashState state;

  if (Init( &state, hashbitlen)) return FAIL;
  if (Update( &state, data, databitlen)) return FAIL;
  if (Final( &state, hashval)) return FAIL;
  return SUCCESS;
}



#ifdef SELF_TEST

int main()
{
  int hashbitlen = 1024;
  hashState   state;
  u8 hashbuf[MARACA_LEN];
  BitSequence *hashval = (BitSequence *)hashbuf;
  BitSequence buf[1<<16];
  int i;
  u8 starttime;
  u8 endtime;

  u8 key[MARACA_LEN];
  memset( key, 0, BYTES_PER_BLOCK);
  memset( buf, 42, sizeof(buf));

  /* hash the empty string once */
  if (1)
  {
    DataLength databitlen = 0;
    printf( "Hash the empty string once:\n");
    Hash( hashbitlen, buf, databitlen, hashval);
    printf( "Message digest for the empty string:\n");
    for (i=0; i<MARACA_LEN; ++i)
    {
      printf( "%.16llx ", ((u8 *)hashbuf)[i]);
      if ((i%4) == 3) printf("\n");
    }
    printf( "\n");
  }

  /* hash one block */
  if (1)
  {
    DataLength databitlen = 8*(1<<7);
    printf( "Hash one block:\n");
    Hash( hashbitlen, buf, databitlen, hashval);
    printf( "Message digest for one block:\n");
    for (i=0; i<MARACA_LEN; ++i)
    {
      printf( "%.16llx ", ((u8 *)hashbuf)[i]);
      if ((i%4) == 3) printf("\n");
    }
    printf( "\n");
  }

  /* hash two blocks */
  if (1)
  {
    DataLength databitlen = 2*8*(1<<7);
    printf( "Hash two blocks:\n");
    Hash( hashbitlen, buf, databitlen, hashval);
    printf( "Message digest for two blocks:\n");
    for (i=0; i<MARACA_LEN; ++i)
    {
      printf( "%.16llx ", ((u8 *)hashbuf)[i]);
      if ((i%4) == 3) printf("\n");
    }
    printf( "\n");
  }

  /* hash the empty string 2^^16 times */
  if (0)
  {
    DataLength databitlen = 0;
    printf( "time for empty string 2^^16 times:\n");
    starttime = GetTickCount();
    for (i=0; i<(1<<16); ++i)
    {
      Hash( hashbitlen, buf, databitlen, hashval);
    }
    endtime = GetTickCount();
    printf( "   %d millisecond\n", endtime-starttime);
    for (i=0; i<MARACA_LEN; ++i)
    {
      printf( "%.16llx ", ((u8 *)hashbuf)[i]);
      if ((i%4) == 3) printf("\n");
    }
    printf( "\n");
  }


  /* Do a single hash of 2^^30 bytes */
  /* Update the hash with a single 1<<16 byte buffer 1<<14 times */
  if (0)
  {
    DataLength databitlen = 8*((1<<16));  /* length in bits */
    printf( "time for 2^^30 bytes:\n");
    starttime = GetTickCount();
    InitWithKey( &state, hashbitlen, (BitSequence *)key, 1024);
    for (i=0; i < (1<<30)/bytes(databitlen); ++i)
    {
      Update( &state, buf, databitlen);
    }
    Final( &state, hashval);
    endtime = GetTickCount();
    printf( "   %d millisecond\n", (unsigned int)(endtime-starttime));
    for (i=0; i<MARACA_LEN; ++i)
    {
      printf( "%.16llx ", ((u8 *)hashbuf)[i]);
      if ((i%4) == 3) printf("\n");
    }
    printf( "\n");
  }
    
  printf( "size of state: %d\n", sizeof(hashState));
}

#endif /* SELF_TEST */
