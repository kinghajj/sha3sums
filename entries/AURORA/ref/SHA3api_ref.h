/******************************************************************************
 * Copyright 2008 Sony Corporation
 *
 * aurora_ref.h
 *
 * "AURORA: A Cryptographic Hash Algorithm Family"
 * Header file of Reference ANSI C code
 *
 * Version 1.0.0 (October 17 2008)
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/


#ifndef AURORA_REF_H_INCLUDED
#define AURORA_REF_H_INCLUDED


typedef unsigned char BitSequence;

typedef unsigned long long DataLength;

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;

/* AURORA-224/256/384/512/224M/256M parameters */
#define AURORA_ROUNDS 17
#define AURORA_BLK_SIZE 64

/* AURORA-224/256/224M/256M parameters */
#define AURORA256_BLK_SIZE AURORA_BLK_SIZE
#define AURORA256_DIGEST_SIZE 32
#define AURORA256_DIGEST_SIZE_BIT (AURORA256_DIGEST_SIZE * 8)
#define AURORA224_DIGEST_SIZE 28
#define AURORA224_DIGEST_SIZE_BIT (AURORA224_DIGEST_SIZE * 8)

/* AURORA-384/512 parameters */
#define AURORA512_BLK_SIZE AURORA_BLK_SIZE
#define AURORA512_DIGEST_SIZE 64
#define AURORA512_DIGEST_SIZE_BIT (AURORA512_DIGEST_SIZE * 8)
#define AURORA384_DIGEST_SIZE 48
#define AURORA384_DIGEST_SIZE_BIT (AURORA384_DIGEST_SIZE * 8)


/* AURORA-224/256/384/512 context */
typedef struct {
  BitSequence h[64];
  BitSequence blk_num[8];
  int cnt;
  BitSequence blk_idx;
  BitSequence buff[AURORA_BLK_SIZE];
  const BitSequence *con_iv;
  const BitSequence *con_mask;
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

/* optional APIs for MCR modes */
HashReturn InitMcr(hashState *state, int hashbitlen);
HashReturn HashMcr(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);


#ifdef __cplusplus
}
#endif /* ?__cplusplus */

#endif /* ?AURORA_REF_H_INCLUDED */


/* end of file */

