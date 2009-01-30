/******************************************************************************
 * Copyright 2008 Sony Corporation
 *
 * aurora_opt64.h
 *
 * "AURORA: A Cryptographic Hash Algorithm Family"
 * Header file of optimized ANSI C code for 64-bit processors
 *
 * Version 1.0.0 (October 17 2008)
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/


#ifndef _AURORA_OPT64_H_INCLUDED
#define _AURORA_OPT64_H_INCLUDED


typedef unsigned char BitSequence;


#ifndef _MSC_VER
typedef unsigned long long AURORA_UINT64;
#define u64(h) 0x##h##ULL
#else /* _MSC_VER */
#include <windows.h>
typedef ULONGLONG AURORA_UINT64;
#define u64(h) 0x##h##ui64
#endif /* ?_MSC_VER */


/* assumption: 'unsigned long long' is 64-bit unsigned data type */
typedef AURORA_UINT64 DataLength;

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

/* AURORA parameters */
#define AURORA_BLK_SIZE 64
#define AURORA_ROUNDS 17

/* AURORA-256 parameters */
#define AURORA256_BLK_SIZE AURORA_BLK_SIZE
#define AURORA256_DIGEST_SIZE 32
#define AURORA224_DIGEST_SIZE 28
#define AURORA256_DIGEST_SIZE_BIT (AURORA256_DIGEST_SIZE * 8)
#define AURORA224_DIGEST_SIZE_BIT (AURORA224_DIGEST_SIZE * 8)

/* AURORA-512/384 parameters */
#define AURORA512_BLK_SIZE AURORA_BLK_SIZE
#define AURORA512_DIGEST_SIZE 64
#define AURORA384_DIGEST_SIZE 48
#define AURORA512_DIGEST_SIZE_BIT (AURORA512_DIGEST_SIZE * 8)
#define AURORA384_DIGEST_SIZE_BIT (AURORA384_DIGEST_SIZE * 8)

/* AURORA context */
typedef struct {
  AURORA_UINT64 h[8];
  DataLength blk_num;
  int cnt;
  AURORA_UINT64 blk_idx;
  BitSequence buff[AURORA_BLK_SIZE];
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


#endif /* ?_AURORA_OPT64_H_INCLUDED */


/* end of file */

