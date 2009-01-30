/******************************************************************************
 * Copyright 2008 Sony Corporation
 *
 * aurora_opt32.h
 *
 * "AURORA: A Cryptographic Hash Algorithm Family"
 * Header file of optimized ANSI C code for 32-bit processors
 *
 * Version 1.0.0 (October 17 2008)
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/


#ifndef _AURORA_OPT32_H_INCLUDED
#define _AURORA_OPT32_H_INCLUDED


typedef unsigned char BitSequence;

/* assumption: 'unsigned long long' is 64-bit unsigned data type */
typedef unsigned long long DataLength;

#ifndef __x86_64__
typedef unsigned long AURORA_UINT32;
#else
typedef unsigned int AURORA_UINT32;
#endif /* ?__x86_64__ */

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

/* AURORA parameters */
#define AURORA_BLK_SIZE 64
#define AURORA_ROUNDS 17

/* AURORA-256 parameters */
#define AURORA256_DIGEST_SIZE 32
#define AURORA224_DIGEST_SIZE 28
#define AURORA256_DIGEST_SIZE_BIT (AURORA256_DIGEST_SIZE * 8)
#define AURORA224_DIGEST_SIZE_BIT (AURORA224_DIGEST_SIZE * 8)

/* AURORA-512/384 parameters */
#define AURORA512_DIGEST_SIZE 64
#define AURORA384_DIGEST_SIZE 48
#define AURORA512_DIGEST_SIZE_BIT (AURORA512_DIGEST_SIZE * 8)
#define AURORA384_DIGEST_SIZE_BIT (AURORA384_DIGEST_SIZE * 8)

/* AURORA context */
typedef struct {
  AURORA_UINT32 h[16];
  DataLength blk_num;
  int cnt;
  AURORA_UINT32 blk_idx;
  unsigned char buff[AURORA_BLK_SIZE];
} AURORA_CTX;

typedef struct {
  int hashbitlen;

  /* The following are algorithm-specific parameters.           *
   * Users do not have to set any parameter to these variables. */
  AURORA_CTX ctx;
  void (*HashUpdate) (AURORA_CTX *, const BitSequence *, DataLength );
  void (*HashFinal) (BitSequence *, AURORA_CTX *);
} hashState;


#ifdef __cplusplus
extern "C" {
#endif /* ?__cplusplus */


HashReturn Init(hashState *state, int hashbitlen);
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Final(hashState *state, BitSequence *hashval);
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);


#ifdef __cplusplus
}
#endif /* ?__cplusplus */


#endif /* ?_AURORA_OPT32_H_INCLUDED */


/* end of file */

