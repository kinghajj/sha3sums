/******************************************************************************
 * Copyright 2008 Sony Corporation
 *
 * aurora_ref.c
 *
 * "AURORA: A Cryptographic Hash Algorithm Family"
 * Reference ANSI C code
 *
 * Version 1.0.0 (October 17 2008)
 *
 * THIS CODE IS FURNISHED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND.
 *
 *****************************************************************************/


#include "SHA3api_ref.h"


/*
 * Usage
 *
 * input  : data (databitlen [bits])
 *          databitlen (bit length of data)
 * output : hashval
 *
 * ----- AURORA-224 -----
 * hashState st;
 * Init(&st, 224); -> Update(&st, data, databitlen); -> Final(&st, hashval);
 * or
 * Hash(224, data, databitlen, hashval);
 *
 * ----- AURORA-256 -----
 * hashState st;
 * Init(&st, 256); -> Update(&st, data, databitlen); -> Final(&st, hashval);
 * or
 * Hash(256, data, databitlen, hashval);
 *
 * ----- AURORA-384 -----
 * hashState st;
 * Init(&st, 384); -> Update(&st, data, databitlen); -> Final(&st, hashval);
 * or
 * Hash(384, data, databitlen, hashval);
 *
 * ----- AURORA-512 -----
 * hashState st;
 * Init(&st, 512); -> Update(&st, data, databitlen); -> Final(&st, hashval);
 * or
 * Hash(512, data, databitlen, hashval);
 *
 * ----- AURORA-224M -----
 * hashState st;
 * InitMcr(&st, 224); -> Update(&st, data, databitlen); -> Final(&st, hashval);
 * or
 * HashMcr(224, data, databitlen, hashval);
 *
 * ----- AURORA-256M -----
 * hashState st;
 * InitMcr(&st, 256); -> Update(&st, data, databitlen); -> Final(&st, hashval);
 * or
 * HashMcr(256, data, databitlen, hashval);
 */


static void ByteCpy(BitSequence *dst, const BitSequence *src, int bytelen);
static void ByteXor(BitSequence *dst, const BitSequence *src, int bytelen);
static BitSequence AuroraMul(BitSequence x, BitSequence y);
static void AuroraFXor(BitSequence *y, const BitSequence *x, const BitSequence *cirmat);
static void AuroraBD(BitSequence *y, const BitSequence *x);
static void AuroraOneRound(BitSequence *inout, const BitSequence *cirmat0, const BitSequence *cirmat1);
static void AuroraConUpdate(BitSequence *con, BitSequence *iv, const BitSequence *mask);
static void AuroraRotLConXor(BitSequence *inout, const BitSequence *con, const BitSequence mask, int rotval);
static void AuroraRotRConXor(BitSequence *inout, const BitSequence *con, const BitSequence mask, int rotval);
static void AuroraPROTLXor(BitSequence *dst, const BitSequence *x);
static void AuroraPROTRXor(BitSequence *dst, const BitSequence *y);

static void Aurora256CF(BitSequence *cv, const BitSequence *m, const BitSequence mask, const BitSequence *con_iv, const BitSequence *con_mask);
static void Aurora512CF(BitSequence *cv, const BitSequence *m, const BitSequence mask, const BitSequence *con_iv, const BitSequence *con_mask);
static void Aurora512CFMF(AURORA_CTX *hctx);
static void Aurora256MFF(BitSequence *cv);

static void AuroraAddBlk(BitSequence *blk_num);
static void AuroraInitCommon(AURORA_CTX *hctx, const BitSequence iv);

static void Aurora224Init(AURORA_CTX *hctx);
static void Aurora256Init(AURORA_CTX *hctx);
static void Aurora256Update(AURORA_CTX *hctx, const BitSequence *msg, DataLength msg_bitlen);
static void Aurora256Final(BitSequence *digest, AURORA_CTX *hctx);
static void Aurora224Final(BitSequence *digest, AURORA_CTX *hctx);

static void Aurora384Init(AURORA_CTX *hctx);
static void Aurora512Init(AURORA_CTX *hctx);
static void Aurora512Update(AURORA_CTX *hctx, const BitSequence *msg, DataLength msg_bitlen);
static void Aurora512Final(BitSequence *digest, AURORA_CTX *hctx);
static void Aurora384Final(BitSequence *digest, AURORA_CTX *hctx);

static void Aurora224McrInit(AURORA_CTX *hctx);
static void Aurora256McrInit(AURORA_CTX *hctx);
static void Aurora256McrFinal(BitSequence *digest, AURORA_CTX *hctx);
static void Aurora224McrFinal(BitSequence *digest, AURORA_CTX *hctx);


/* AURORA S-box */
const BitSequence aurora_sbx[256] = {
  0xd9U, 0xdcU, 0xd3U, 0x69U, 0xbdU, 0x00U, 0x4dU, 0xebU,
  0x02U, 0x24U, 0x57U, 0xc2U, 0xb8U, 0x5dU, 0xb7U, 0x6dU,
  0xf5U, 0x40U, 0x37U, 0x4eU, 0x19U, 0xd8U, 0x64U, 0x62U,
  0x9dU, 0x34U, 0x0fU, 0x7cU, 0xecU, 0xceU, 0x94U, 0x04U,
  0xd1U, 0x8aU, 0x74U, 0xfbU, 0xe7U, 0x87U, 0x12U, 0x23U,
  0xb5U, 0x5cU, 0x1aU, 0xbbU, 0x42U, 0x49U, 0x18U, 0x85U,
  0x11U, 0x46U, 0x0dU, 0x71U, 0x67U, 0x8fU, 0xc6U, 0x50U,
  0x58U, 0xfdU, 0x4bU, 0xa4U, 0xcdU, 0x8eU, 0x99U, 0x1fU,
  0xadU, 0x63U, 0xc9U, 0x6bU, 0xf7U, 0x28U, 0x9fU, 0x65U,
  0x2fU, 0x5fU, 0x61U, 0x73U, 0x3dU, 0x8bU, 0x0eU, 0x1bU,
  0x33U, 0xe0U, 0xacU, 0x26U, 0xa1U, 0xe3U, 0xf3U, 0x82U,
  0x83U, 0x75U, 0x44U, 0x90U, 0x13U, 0xafU, 0xf0U, 0x07U,
  0x96U, 0x21U, 0xf8U, 0x3fU, 0xa2U, 0x98U, 0x9aU, 0xa3U,
  0x91U, 0x4cU, 0x7fU, 0x92U, 0x97U, 0xeaU, 0x01U, 0x1cU,
  0x1eU, 0x2dU, 0x89U, 0x39U, 0xe6U, 0x9cU, 0x0aU, 0x54U,
  0x0cU, 0x51U, 0x6cU, 0x43U, 0xaeU, 0xdbU, 0x53U, 0x59U,
  0xa6U, 0xf4U, 0x06U, 0xdaU, 0xe2U, 0x78U, 0x1dU, 0x29U,
  0x30U, 0xe1U, 0x35U, 0xfcU, 0xedU, 0xbcU, 0x47U, 0xd5U,
  0xc0U, 0xabU, 0xccU, 0xa8U, 0x80U, 0x2bU, 0x09U, 0xb0U,
  0x93U, 0xd4U, 0xc5U, 0xb3U, 0xd0U, 0xdfU, 0xa9U, 0xaaU,
  0x7aU, 0x36U, 0x2aU, 0xd6U, 0xb2U, 0xfaU, 0xe8U, 0xb1U,
  0xa0U, 0x68U, 0x5aU, 0x81U, 0x48U, 0x08U, 0x17U, 0xc7U,
  0xfeU, 0x76U, 0xbfU, 0xc4U, 0xf2U, 0x3eU, 0x4aU, 0x0bU,
  0x10U, 0x14U, 0xf1U, 0xefU, 0xa7U, 0x27U, 0xe5U, 0xc8U,
  0xdeU, 0x9bU, 0x8dU, 0x3cU, 0x56U, 0xd7U, 0x8cU, 0x60U,
  0x6aU, 0x79U, 0xeeU, 0xa5U, 0x31U, 0x2eU, 0x77U, 0x41U,
  0xffU, 0x95U, 0xddU, 0x25U, 0x3bU, 0x55U, 0xcaU, 0x52U,
  0x9eU, 0x2cU, 0x15U, 0x4fU, 0xe4U, 0x16U, 0x70U, 0x7dU,
  0x72U, 0x3aU, 0x7bU, 0x84U, 0xf6U, 0x32U, 0x86U, 0x03U,
  0xb4U, 0x38U, 0x6fU, 0xb9U, 0xc1U, 0x45U, 0x88U, 0xe9U,
  0xbaU, 0xb6U, 0x6eU, 0x5eU, 0xbeU, 0x7eU, 0x20U, 0xf9U,
  0x22U, 0x66U, 0x05U, 0xd2U, 0xcbU, 0xc3U, 0xcfU, 0x5bU
};

/* Initial values and mask values for generating constant values */
const BitSequence con_iv256[] = {0x6aU, 0x09U, 0xbbU, 0x67U};
const BitSequence con_iv512[] = {0x51U, 0x0eU, 0x9bU, 0x05U};
const BitSequence con_iv256m[] = {0x3cU, 0x6eU, 0xa5U, 0x4fU};

const BitSequence con_mask256[] = {
  0x42U, 0x8aU, 0x71U, 0x37U, 0x26U, 0x11U, 0x3eU, 0xe8U
};
const BitSequence con_mask512[] = {
  0x39U, 0x56U, 0x59U, 0xf1U, 0x9dU, 0x8aU, 0xabU, 0x97U
};
const BitSequence con_mask256m[] = {
  0xb5U, 0xc0U, 0xe9U, 0xb5U, 0x61U, 0x35U, 0x79U, 0xccU
};

/* Circulant matrices for AURORA F-functions */
const BitSequence mat0[4] = {0x01U, 0x02U, 0x02U, 0x03U}; /* cir(1223) */
const BitSequence mat1[4] = {0x01U, 0x06U, 0x08U, 0x02U}; /* cir(1682) */
const BitSequence mat2[4] = {0x03U, 0x01U, 0x02U, 0x02U}; /* cir(3122) */
const BitSequence mat3[4] = {0x06U, 0x08U, 0x02U, 0x01U}; /* cir(6821) */


static void ByteCpy(BitSequence *dst, const BitSequence *src, int bytelen)
{
  while(bytelen-- > 0){
    *dst++ = *src++;
  }
}

static void ByteXor(BitSequence *dst, const BitSequence *src, int bytelen)
{
  while(bytelen-- > 0){
    *dst++ ^= *src++;
  }
}

static BitSequence AuroraMul(BitSequence x, BitSequence y)
{
  /* assumption: y is at most 4-bit value */
  BitSequence xy = 0;
  int i;

  /* multiplication over GF(2^8) (p(x) = '11b') */
  for(i = 0; i < 4; i++){
    if(y & 0x01U){
      xy ^= x;
    }
    y >>= 1;
    if(x & 0x80U){
      x ^= 0x0dU;
    }
    x = ((x << 1) | (x >> 7));
  }

  return xy;
}

static void AuroraFXor(BitSequence *y, const BitSequence *x, const BitSequence *cirmat)
{
  BitSequence z[4];

  /* Substitution layer */
  z[0] = aurora_sbx[x[0]];
  z[1] = aurora_sbx[x[1]];
  z[2] = aurora_sbx[x[2]];
  z[3] = aurora_sbx[x[3]];
  /* Diffusion layer */
  y[0] = AuroraMul(z[0], cirmat[0]) ^ AuroraMul(z[1], cirmat[1]) ^ AuroraMul(z[2], cirmat[2]) ^ AuroraMul(z[3], cirmat[3]);
  y[1] = AuroraMul(z[0], cirmat[3]) ^ AuroraMul(z[1], cirmat[0]) ^ AuroraMul(z[2], cirmat[1]) ^ AuroraMul(z[3], cirmat[2]);
  y[2] = AuroraMul(z[0], cirmat[2]) ^ AuroraMul(z[1], cirmat[3]) ^ AuroraMul(z[2], cirmat[0]) ^ AuroraMul(z[3], cirmat[1]);
  y[3] = AuroraMul(z[0], cirmat[1]) ^ AuroraMul(z[1], cirmat[2]) ^ AuroraMul(z[2], cirmat[3]) ^ AuroraMul(z[3], cirmat[0]);
  /* Xoring after F */
  y[4] = x[4] ^ y[0];
  y[5] = x[5] ^ y[1];
  y[6] = x[6] ^ y[2];
  y[7] = x[7] ^ y[3];
}

static void AuroraBD(BitSequence *y, const BitSequence *x)
{
  const int pi[32] = {
     4, 29, 22, 15,  8,  9, 10, 11, 12,  5, 30, 23, 16, 17, 18, 19,
    20, 13,  6, 31, 24, 25, 26, 27, 28, 21, 14,  7,  0,  1,  2,  3
  };
  int i;

  for(i = 0; i < 32; i++){
    y[i] = x[pi[i]];
  }
}

static void AuroraOneRound(BitSequence *inout, const BitSequence *cirmat0, const BitSequence *cirmat1)
{
  BitSequence x[32];

  /* Byte Diffusion Function: BD */
  AuroraBD(x, inout);
  /* F-Functions */
  AuroraFXor(inout + 0,  x + 0,  cirmat0);
  AuroraFXor(inout + 8,  x + 8,  cirmat1);
  AuroraFXor(inout + 16, x + 16, cirmat0);
  AuroraFXor(inout + 24, x + 24, cirmat1);
}

static void AuroraConUpdate(BitSequence *con, BitSequence *iv, const BitSequence *mask)
{
  BitSequence tmp;

  con[0]  = iv[0] ^ mask[0];
  con[1]  = iv[1] ^ mask[1];
  con[2]  = ~iv[1]; /* 8-bit left rotation */
  con[3]  = ~iv[0];
  con[4]  = iv[2] ^ mask[2];
  con[5]  = iv[3] ^ mask[3];
  con[6]  = ~iv[3]; /* 8-bit left rotation */
  con[7]  = ~iv[2];
  con[8]  = iv[1]; /* 8-bit left rotation */
  con[9]  = iv[0];
  con[10] = iv[0] ^ mask[4];
  con[11] = iv[1] ^ mask[5];
  con[12] = (iv[2] >> 7) | (iv[3] << 1); /* 9-bit left rotation */
  con[13] = (iv[3] >> 7) | (iv[2] << 1);
  con[14] = iv[2] ^ mask[6];
  con[15] = iv[3] ^ mask[7];
  
  /* updating T */
  if(iv[0] & 0x80U){
    iv[0] ^= 0x54U;
    iv[1] ^= 0x18U;
  }
  tmp = iv[0] >> 7;
  iv[0] = (iv[0] << 1) | (iv[1] >> 7);
  iv[1] = (iv[1] << 1) | tmp;
  
  /* updating U */
  if(iv[3] & 0x01U){
    iv[2] ^= 0xa8U;
    iv[3] ^= 0x30U;
  }
  tmp = iv[2] << 7;
  iv[2] = (iv[2] >> 1) | (iv[3] << 7);
  iv[3] = (iv[3] >> 1) | tmp;
   
  return ;
}

static void AuroraRotLConXor(BitSequence *inout, const BitSequence *con, const BitSequence mask, int rotval)
{
  inout[4]  ^= (con[0]  << rotval) ^ (con[1]  >> (8 - rotval));
  inout[5]  ^= (con[1]  << rotval) ^ (con[2]  >> (8 - rotval));
  inout[6]  ^= (con[2]  << rotval) ^ (con[3]  >> (8 - rotval));
  inout[7]  ^= (con[3]  << rotval) ^ (con[0]  >> (8 - rotval));

  inout[12] ^= (con[4]  << rotval) ^ (con[5]  >> (8 - rotval));
  inout[13] ^= (con[5]  << rotval) ^ (con[6]  >> (8 - rotval));
  inout[14] ^= (con[6]  << rotval) ^ (con[7]  >> (8 - rotval));
  inout[15] ^= (con[7]  << rotval) ^ (con[4]  >> (8 - rotval));

  inout[20] ^= (con[8]  << rotval) ^ (con[9]  >> (8 - rotval));
  inout[21] ^= (con[9]  << rotval) ^ (con[10] >> (8 - rotval));
  inout[22] ^= (con[10] << rotval) ^ (con[11] >> (8 - rotval));
  inout[23] ^= (con[11] << rotval) ^ (con[8]  >> (8 - rotval));

  inout[28] ^= (con[12] << rotval) ^ (con[13] >> (8 - rotval)) ^ mask;
  inout[29] ^= (con[13] << rotval) ^ (con[14] >> (8 - rotval)) ^ mask;
  inout[30] ^= (con[14] << rotval) ^ (con[15] >> (8 - rotval)) ^ mask;
  inout[31] ^= (con[15] << rotval) ^ (con[12] >> (8 - rotval)) ^ mask;
}

static void AuroraRotRConXor(BitSequence *inout, const BitSequence *con, const BitSequence mask, int rotval)
{
  inout[4]  ^= (con[0]  >> rotval) ^ (con[3]  << (8 - rotval));
  inout[5]  ^= (con[1]  >> rotval) ^ (con[0]  << (8 - rotval));
  inout[6]  ^= (con[2]  >> rotval) ^ (con[1]  << (8 - rotval));
  inout[7]  ^= (con[3]  >> rotval) ^ (con[2]  << (8 - rotval));

  inout[12] ^= (con[4]  >> rotval) ^ (con[7]  << (8 - rotval));
  inout[13] ^= (con[5]  >> rotval) ^ (con[4]  << (8 - rotval));
  inout[14] ^= (con[6]  >> rotval) ^ (con[5]  << (8 - rotval));
  inout[15] ^= (con[7]  >> rotval) ^ (con[6]  << (8 - rotval));

  inout[20] ^= (con[8]  >> rotval) ^ (con[11] << (8 - rotval));
  inout[21] ^= (con[9]  >> rotval) ^ (con[8]  << (8 - rotval));
  inout[22] ^= (con[10] >> rotval) ^ (con[9]  << (8 - rotval));
  inout[23] ^= (con[11] >> rotval) ^ (con[10] << (8 - rotval));

  inout[28] ^= (con[12] >> rotval) ^ (con[15] << (8 - rotval)) ^ mask;
  inout[29] ^= (con[13] >> rotval) ^ (con[12] << (8 - rotval)) ^ mask;
  inout[30] ^= (con[14] >> rotval) ^ (con[13] << (8 - rotval)) ^ mask;
  inout[31] ^= (con[15] >> rotval) ^ (con[14] << (8 - rotval)) ^ mask;
}

static void AuroraPROTLXor(BitSequence *dst, const BitSequence *x)
{
  BitSequence z[32];

  /* PROTL */
  ByteCpy(z + 0,  x + 0,  4);  /* Z0 = X0 */
  ByteCpy(z + 8,  x + 8,  4);  /* Z2 = X2 */
  ByteCpy(z + 16, x + 16, 16); /* Z4,5,6,7 = X4,5,6,7 */
  /* Z1 || Z3 = (X1 || X3) <<< 1 */
  z[4]  = (x[4]  << 1) | (x[5]  >> 7);
  z[5]  = (x[5]  << 1) | (x[6]  >> 7);
  z[6]  = (x[6]  << 1) | (x[7]  >> 7);
  z[7]  = (x[7]  << 1) | (x[12] >> 7);
  z[12] = (x[12] << 1) | (x[13] >> 7);
  z[13] = (x[13] << 1) | (x[14] >> 7);
  z[14] = (x[14] << 1) | (x[15] >> 7);
  z[15] = (x[15] << 1) | (x[4]  >> 7);

  /* XOR */
  ByteXor(dst, z, 32);
}

static void AuroraPROTRXor(BitSequence *dst, const BitSequence *y)
{
  BitSequence z[32];

  /* PROTR */
  ByteCpy(z + 0,  y + 0,  4);  /* Z0 = Y0 */
  ByteCpy(z + 8,  y + 8,  4);  /* Z2 = Y2 */
  ByteCpy(z + 16, y + 16, 16); /* Z4,5,6,7 = Y4,5,6,7 */
  /* Z1 || Z3 = (Y1 || Y3) >>> 1 */
  z[4]  = (y[4]  >> 1) | (y[15] << 7);
  z[5]  = (y[5]  >> 1) | (y[4]  << 7);
  z[6]  = (y[6]  >> 1) | (y[5]  << 7);
  z[7]  = (y[7]  >> 1) | (y[6]  << 7);
  z[12] = (y[12] >> 1) | (y[7]  << 7);
  z[13] = (y[13] >> 1) | (y[12] << 7);
  z[14] = (y[14] >> 1) | (y[13] << 7);
  z[15] = (y[15] >> 1) | (y[14] << 7);

  /* XOR */
  ByteXor(dst, z, 32);
}


/*
 * Aurora256CF
 *
 * AURORA-224/256 compression function
 */
static void Aurora256CF(BitSequence *cv, const BitSequence *m, const BitSequence mask, const BitSequence *con_iv, const BitSequence *con_mask)
{
  BitSequence ml[32], mr[32], x[32];
  BitSequence t[4];
  BitSequence con[16];
  int r;

  /* init. */
  ByteCpy(ml, m + 0,  32);
  ByteCpy(mr, m + 32, 32);
  ByteCpy(x, cv, 32);
  ByteCpy(t, con_iv, 4);

  for(r = 0; r < AURORA_ROUNDS; r++){
    /* Updating constant value */
    AuroraConUpdate(con, t, con_mask);
    if(0 == (r % 2)){
      /* MS_L */
      if(r < (AURORA_ROUNDS - 1)){
	AuroraRotLConXor(ml, con, 0x00U, 1); /* XORing with CONM_L */
      }
      AuroraPROTLXor(x, ml);
      AuroraOneRound(ml, mat0, mat1); /* MS_L round function (F0,F1) */
    }else{
      /* MS_R */
      AuroraRotRConXor(mr, con, 0x00U, 1); /* XORing with CONM_R */
      AuroraPROTRXor(x, mr);
      AuroraOneRound(mr, mat2, mat3); /* MS_R round function (F2,F3) */
    }
    /* CP */
    AuroraRotLConXor(x, con, mask, 0); /* XORing with CONC */
    AuroraOneRound(x, mat1, mat0); /* CP round function (F1,F0) */
  }
  AuroraPROTRXor(x, mr);

  /* XORing after CP */
  ByteXor(cv, x, 32);
}


/*
 * Aurora512CF
 *
 * AURORA-384/512(224M/256M) compression function
 */
static void Aurora512CF(BitSequence *cv, const BitSequence *m, const BitSequence mask, const BitSequence *con_iv, const BitSequence *con_mask)
{
  BitSequence ml[32], mr[32], xl[32], xr[32];
  BitSequence t[4];
  BitSequence con[16];
  int r;

  /* init. */
  ByteCpy(ml, m + 0,  32);
  ByteCpy(mr, m + 32, 32);
  ByteCpy(xl, cv + 0,  32);
  ByteCpy(xr, cv + 32, 32);
  ByteCpy(t, con_iv, 4);

  for(r = 0; r < AURORA_ROUNDS; r++){
    /* Updating constant value */
    AuroraConUpdate(con, t, con_mask);
    if(0 == (r % 2)){
      /* MS_L */
      if(r < (AURORA_ROUNDS - 1)){
	AuroraRotLConXor(ml, con, 0x00U, 1); /* XORing with CONM_L */
      }
      AuroraPROTLXor(xl, ml);
      AuroraPROTLXor(xr, ml);
      AuroraOneRound(ml, mat0, mat1); /* M_L round function (F0,F1) */
    }else{
      /* MS_R */
      AuroraRotRConXor(mr, con, 0x00U, 1); /* XORing with CONM_R */
      AuroraPROTRXor(xl, mr);
      AuroraPROTRXor(xr, mr);
      AuroraOneRound(mr, mat2, mat3); /* M_R round function (F2,F3) */
    }
    /* CP_L */
    AuroraRotLConXor(xl, con, mask, 0); /* XORing with CONC_L */
    AuroraOneRound(xl, mat1, mat0); /* CP_L round function (F1,F0) */
    /* CP_R */
    AuroraRotLConXor(xr, con, mask, 3); /* XORing with CONC_R */
    AuroraOneRound(xr, mat3, mat2); /* CP_R round function (F3,F2) */
  }
  AuroraPROTRXor(xl, mr);
  AuroraPROTRXor(xr, mr);

  /* XORing after CP_L and CP_R */
  ByteXor(cv + 0,  xl, 32);
  ByteXor(cv + 32, xr, 32);
}


/*
 * Aurora512CFMF
 *
 * AURORA-384/512(224M/256M) compression function and mixing function
 */
static void Aurora512CFMF(AURORA_CTX *hctx)
{
  if(hctx->blk_idx >= 0x08U){
    /* mixing function */
    Aurora512CF(hctx->h, hctx->h, hctx->blk_idx, hctx->con_iv, hctx->con_mask);
    hctx->blk_idx = 0U;
  }
  /* compression function */
  Aurora512CF(hctx->h, hctx->buff, hctx->blk_idx++, hctx->con_iv, hctx->con_mask);
}


/*
 * Aurora256MFF
 *
 * AURORA-224M/256M mixing function for finalization
 */
static void Aurora256MFF(BitSequence *cv)
{
  BitSequence mr[32], x[32];
  BitSequence t[4];
  BitSequence con[16];
  int r;

  /* init. */
  ByteCpy(mr, cv + 32, 32);
  ByteCpy(x, cv + 0,  32);
  ByteCpy(t, con_iv256m, 4);

  for(r = 0; r < AURORA_ROUNDS; r++){
    /* Updating constant value */
    AuroraConUpdate(con, t, con_mask256m);
    if(r % 2){
      /* MS_R */
      AuroraRotRConXor(mr, con, 0x00U, 1);
      AuroraPROTRXor(x, mr);
      AuroraOneRound(mr, mat2, mat3); /* MS_R round function (F2,F3) */
    }
    /* CP_L */
    AuroraRotLConXor(x, con, 0x09U, 0);
    AuroraOneRound(x, mat1, mat0); /* CP_L round function (F1,F0) */
  }
  AuroraPROTRXor(x, mr);

  /* XORing after CP_L */
  ByteXor(cv, x, 32);
}


static void AuroraAddBlk(BitSequence *blk_num)
{
  int i;

  for(i = 7; i >= 0; i--){
    if(++blk_num[i]){
      break;
    }
  }
}

static void AuroraInitCommon(AURORA_CTX *hctx, const BitSequence iv)
{
  int i;

  for(i = 0; i < 64; i++){
    hctx->h[i] = iv;
  }
  for(i = 0; i < 8; i++){
    hctx->blk_num[i] = 0U;
  }
  hctx->cnt = 0U;
  hctx->blk_idx = 0U;
}


/*-----------------------------------------------------------------------------
 * for AURORA-224/256
 *---------------------------------------------------------------------------*/

static void Aurora224Init(AURORA_CTX *hctx)
{
  AuroraInitCommon(hctx, 0xffU);
  hctx->con_iv = con_iv256;
  hctx->con_mask = con_mask256;
}

static void Aurora256Init(AURORA_CTX *hctx)
{
  AuroraInitCommon(hctx, 0x00U);
  hctx->con_iv = con_iv256;
  hctx->con_mask = con_mask256;
}
  
static void Aurora256Update(AURORA_CTX *hctx, const BitSequence *msg, DataLength msg_bitlen)
{
  int byte_cnt = hctx->cnt / 8;
  int bit_ofs = hctx->cnt & 0x07;
  int msg_ofs = ((int) (msg_bitlen & 0x07U) + bit_ofs) & 0x07;
  DataLength msg_bytelen = (msg_bitlen + (DataLength) bit_ofs) >> 3;
  BitSequence tmp;

  if((hctx->cnt < 0) || (hctx->cnt >= 512)){
    return ;
  }

  tmp = hctx->buff[byte_cnt];
  hctx->cnt -= bit_ofs;
  while(msg_bytelen--){
    if(bit_ofs){
      hctx->buff[byte_cnt++] = tmp | (*msg >> bit_ofs);
      tmp = *msg++ << (8 - bit_ofs);
    }else{
      hctx->buff[byte_cnt++] = *msg++;
    }
    hctx->cnt += 8;
    if(byte_cnt >= 64){
      Aurora256CF(hctx->h, hctx->buff, 0x00U, hctx->con_iv, hctx->con_mask);
      AuroraAddBlk(hctx->blk_num);
      byte_cnt = 0;
      hctx->cnt = 0;
    }
  }
  if(bit_ofs){
    hctx->buff[byte_cnt] = tmp & (0xffU << (8 - msg_ofs));
    hctx->cnt += msg_ofs;
  }else{
    if(msg_bitlen &= 0x07U){
      hctx->buff[byte_cnt] = *msg & (0xffU << (8 - (int) msg_bitlen));
      hctx->cnt += (int) msg_bitlen;
    }
  }
}

static void Aurora256Final(BitSequence *digest, AURORA_CTX *hctx)
{
  int byte_cnt = hctx->cnt / 8;

  if((hctx->cnt < 0) || (hctx->cnt >= 512)){
    return ;
  }

  if(0 != hctx->cnt){
    AuroraAddBlk(hctx->blk_num);
  }

  if(hctx->cnt & 0x07){
    hctx->buff[byte_cnt++] |= 0x80U >> (hctx->cnt & 0x07);
  }else{
    hctx->buff[byte_cnt++] = 0x80U;
  }

  if(hctx->cnt > 447){
    /* extra block */
    while(byte_cnt < AURORA256_BLK_SIZE){
      hctx->buff[byte_cnt++] = 0U;
    }
    byte_cnt = 0;
    Aurora256CF(hctx->h, hctx->buff, 0x00U, hctx->con_iv, hctx->con_mask);
  }

  while(byte_cnt < (AURORA256_BLK_SIZE - 8)){
    hctx->buff[byte_cnt++] = 0U;
  }
  ByteCpy(hctx->buff + AURORA256_BLK_SIZE - 8, hctx->blk_num, 8);

  /* finalization function */
  Aurora256CF(hctx->h, hctx->buff, 0x01U, hctx->con_iv, hctx->con_mask);

  ByteCpy(digest, hctx->h, 32);
}

static void Aurora224Final(BitSequence *digest, AURORA_CTX *hctx)
{
  BitSequence digest256[32];
  int i;

  Aurora256Final(digest256, hctx);
  for(i = 0; i < 4; i++){
    ByteCpy(digest + i * 7, digest256 + i * 8, 7);
  }
}


/*-----------------------------------------------------------------------------
 * for AURORA-384/512
 *---------------------------------------------------------------------------*/

static void Aurora384Init(AURORA_CTX *hctx)
{
  AuroraInitCommon(hctx, 0xffU);
  hctx->con_iv = con_iv512;
  hctx->con_mask = con_mask512;
}

static void Aurora512Init(AURORA_CTX *hctx)
{
  AuroraInitCommon(hctx, 0x00U);
  hctx->con_iv = con_iv512;
  hctx->con_mask = con_mask512;
}

static void Aurora512Update(AURORA_CTX *hctx, const BitSequence *msg, DataLength msg_bitlen)
{
  int byte_cnt = hctx->cnt / 8;
  int bit_ofs = hctx->cnt & 0x07;
  int msg_ofs = ((int) (msg_bitlen & 0x07U) + bit_ofs) & 0x07;
  DataLength msg_bytelen = (msg_bitlen + (DataLength) bit_ofs) >> 3;
  BitSequence tmp;

  if((hctx->cnt < 0) || (hctx->cnt >= 512)){
    return ;
  }

  tmp = hctx->buff[byte_cnt];
  hctx->cnt -= bit_ofs;
  while(msg_bytelen--){
    if(bit_ofs){
      hctx->buff[byte_cnt++] = tmp | (*msg >> bit_ofs);
      tmp = *msg++ << (8 - bit_ofs);
    }else{
      hctx->buff[byte_cnt++] = *msg++;
    }
    hctx->cnt += 8;
    if(byte_cnt >= 64){
      Aurora512CFMF(hctx);
      AuroraAddBlk(hctx->blk_num);
      byte_cnt = 0;
      hctx->cnt = 0;
    }
  }
  if(bit_ofs){
    hctx->buff[byte_cnt] = tmp & (0xffU << (8 - msg_ofs));
    hctx->cnt += msg_ofs;
  }else{
    if(msg_bitlen &= 0x07){
      hctx->buff[byte_cnt] = *msg & (0xffU << (8 - (int) msg_bitlen));
      hctx->cnt += (int) msg_bitlen;
    }
  }
}

static void Aurora512Final(BitSequence *digest, AURORA_CTX *hctx)
{
  int byte_cnt = hctx->cnt / 8;

  if((hctx->cnt < 0) || (hctx->cnt >= 512)){
    return ;
  }

  if(0 != hctx->cnt){
    AuroraAddBlk(hctx->blk_num);
  }

  if(hctx->cnt & 0x07){
    hctx->buff[byte_cnt++] |= 0x80U >> (hctx->cnt & 0x07);
  }else{
    hctx->buff[byte_cnt++] = 0x80U;
  }

  if(hctx->cnt > 447){
    /* extra block */
    while(byte_cnt < AURORA256_BLK_SIZE){
      hctx->buff[byte_cnt++] = 0U;
    }
    byte_cnt = 0;
    Aurora512CFMF(hctx);
  }

  while(byte_cnt < (AURORA256_BLK_SIZE - 8)){
    hctx->buff[byte_cnt++] = 0U;
  }

  ByteCpy(hctx->buff + AURORA256_BLK_SIZE - 8, hctx->blk_num, 8);

  /* final compression */
  Aurora512CFMF(hctx);

  /* final mixing */
  Aurora512CF(hctx->h, hctx->h, 0x09U, hctx->con_iv, hctx->con_mask);

  ByteCpy(digest, hctx->h, 64);
}

static void Aurora384Final(BitSequence *digest, AURORA_CTX *hctx)
{
  BitSequence digest512[64];
  int i;

  Aurora512Final(digest512, hctx);
  for(i = 0; i < 8; i++){
    ByteCpy(digest + 6 * i, digest512 + 8 * i, 6);
  }
}


/*-----------------------------------------------------------------------------
 * for AURORA-256M/224M
 *---------------------------------------------------------------------------*/

static void Aurora224McrInit(AURORA_CTX *hctx)
{
  AuroraInitCommon(hctx, 0xffU);
  hctx->con_iv = con_iv256m;
  hctx->con_mask = con_mask256m;
}

static void Aurora256McrInit(AURORA_CTX *hctx)
{
  AuroraInitCommon(hctx, 0x00U);
  hctx->con_iv = con_iv256m;
  hctx->con_mask = con_mask256m;
}

static void Aurora256McrFinal(BitSequence *digest, AURORA_CTX *hctx)
{
  int byte_cnt = hctx->cnt / 8;

  if((hctx->cnt < 0) || (hctx->cnt >= 512)){
    return ;
  }

  if(0 != hctx->cnt){
    AuroraAddBlk(hctx->blk_num);
  }

  if(hctx->cnt & 0x07){
    hctx->buff[byte_cnt++] |= 0x80U >> (hctx->cnt & 0x07);
  }else{
    hctx->buff[byte_cnt++] = 0x80U;
  }

  if(hctx->cnt > 447){
    /* extra block */
    while(byte_cnt < AURORA256_BLK_SIZE){
      hctx->buff[byte_cnt++] = 0U;
    }
    byte_cnt = 0;
    Aurora512CFMF(hctx);
  }

  while(byte_cnt < (AURORA256_BLK_SIZE - 8)){
    hctx->buff[byte_cnt++] = 0U;
  }

  ByteCpy(hctx->buff + AURORA256_BLK_SIZE - 8, hctx->blk_num, 8);

  /* final compression */
  Aurora512CFMF(hctx);

  /* final mixing */
  Aurora256MFF(hctx->h);

  ByteCpy(digest, hctx->h, 32);
}

static void Aurora224McrFinal(BitSequence *digest, AURORA_CTX *hctx)
{
  BitSequence digest256[32];
  int i;

  Aurora256McrFinal(digest256, hctx);
  for(i = 0; i < 4; i++){
    ByteCpy(digest + i * 7,  digest256 + i * 8,  7);
  }
}


/*-----------------------------------------------------------------------------
 * main
 *---------------------------------------------------------------------------*/

/*
 * Init()
 *
 * input   : state
 *           hashbitlen
 * output  : state (updated)
 * returns : BAD_HASHBITLEN (hashbitlen is invalid) or SUCCESS
 */
HashReturn Init(hashState *state, int hashbitlen)
{
  if(AURORA256_DIGEST_SIZE_BIT == hashbitlen){
    /* AURORA-256 */
    Aurora256Init(&state->ctx);
    state->HashUpdate = Aurora256Update;
    state->HashFinal = Aurora256Final;
  }else if(AURORA224_DIGEST_SIZE_BIT == hashbitlen){
    /* AURORA-224 */
    Aurora224Init(&state->ctx);
    state->HashUpdate = Aurora256Update;
    state->HashFinal = Aurora224Final;
  }else if(AURORA512_DIGEST_SIZE_BIT == hashbitlen){
    /* AURORA-512 */
    Aurora512Init(&state->ctx);
    state->HashUpdate = Aurora512Update;
    state->HashFinal = Aurora512Final;
  }else if(AURORA384_DIGEST_SIZE_BIT == hashbitlen){
    /* AURORA-384 */
    Aurora384Init(&state->ctx);
    state->HashUpdate = Aurora512Update;
    state->HashFinal = Aurora384Final;
  }else{
    /* invalid hashbitlen */
    return BAD_HASHBITLEN;
  }

  state->hashbitlen = hashbitlen;

  return SUCCESS;
}

/*
 * Update()
 *
 * input   : state
 *           data
 *           databitlen
 * output  : state (updated)
 * returns : SUCCESS
 */
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
  state->HashUpdate(&state->ctx, data, databitlen);

  return SUCCESS;
}

/*
 * Final()
 *
 * input   : state
 * output  : hashval
 * returns : SUCCESS
 */
HashReturn Final(hashState *state, BitSequence *hashval)
{
  state->HashFinal(hashval, &state->ctx);

  return SUCCESS;
}

/*
 * Hash()
 *
 * input   : hashbitlen
 *           data
 *           databitlen
 * output  : hashval
 * returns : BAD_HASHBITLEN, FAIL or SUCCESS
 */
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
  hashState state;

  if(BAD_HASHBITLEN == Init(&state, hashbitlen)){
    return BAD_HASHBITLEN;
  }
  Update(&state, data, databitlen);
  Final(&state, hashval);

  return SUCCESS;
}

/*
 * InitMcr()
 *
 * optional API for MCR modes
 *
 * input   : state
 *           hashbitlen
 * output  : state (updated)
 * returns : BAD_HASHBITLEN (hashbitlen is invalid) or SUCCESS
 */
HashReturn InitMcr(hashState *state, int hashbitlen)
{
  if(AURORA256_DIGEST_SIZE_BIT == hashbitlen){
    /* AURORA-256M */
    Aurora256McrInit(&state->ctx);
    state->HashUpdate = Aurora512Update;
    state->HashFinal = Aurora256McrFinal;
  }else if(AURORA224_DIGEST_SIZE_BIT == hashbitlen){
    /* AURORA-224M */
    Aurora224McrInit(&state->ctx);
    state->HashUpdate = Aurora512Update;
    state->HashFinal = Aurora224McrFinal;
  }else{
    /* invalid hashbitlen */
    return BAD_HASHBITLEN;
  }

  state->hashbitlen = hashbitlen;

  return SUCCESS;
}

/*
 * HashMcr()
 *
 * optional API for MCR modes
 *
 * input   : hashbitlen
 *           data
 *           databitlen
 * output  : hashval
 * returns : BAD_HASHBITLEN, FAIL or SUCCESS
 */
HashReturn HashMcr(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
  hashState state;

  if(BAD_HASHBITLEN == InitMcr(&state, hashbitlen)){
    return BAD_HASHBITLEN;
  }
  Update(&state, data, databitlen);
  Final(&state, hashval);

  return SUCCESS;
}



/*-----------------------------------------------------------------------------
 * tests
 *---------------------------------------------------------------------------*/

#ifdef _AURORA_TEST

#include <stdio.h>

void BytePut(const BitSequence *data, int bytelen)
{
  int cnt = 0;

  while(bytelen-- > 0){
    printf("%02x", *data++);
    if(++cnt == 4){
      cnt = 0;
      printf(" ");
    }
  }
  printf("\n");
}

void AuroraSample(void)
{
  const BitSequence msg1[] = {
    "abc"
  };
  const BitSequence msg2[] = {
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  };
  const BitSequence msg3[] = {
    'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
    'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'
  };
  BitSequence hashval[64];
  hashState state;
  int i;

  printf("===== AURORA samples =====\n");

  /* expected results:
   *
   *---------------------------------------------------------------------------
   * M1 = "abc"
   *
   * AURORA-224(M1):
   * 50fddc1c 77601c2c c01cc258 eccc6a10 37646235 860da74b 6e0280af 
   *
   * AURORA-256(M1):
   * 3e0c31c1 8ef5c404 33844fac 2d4acdf4 9e390962 797821a4 9e3553f3 8189917e 
   *
   * AURORA-384(M1):
   * cb7a330f 33ab55ec 98698f49 4ace5996 3dcec8e2 bdfa12f1 f8db22fc 18b5591e
   * a02f267e bdaf1639 49133bf3 b59e94c2 
   *
   * AURORA-512(M1):
   * 6a4cf6d1 18619abd e8c920d5 9806e483 cc90616f 8d1b4db6 b98abab7 00c4ec47 
   * 85eaa639 45bb65e1 52df4901 a1c36f78 9c587f09 49c8e76a a0a8d7de 20f8aa0e 
   *
   * AURORA-224M(M1):
   * d64eaa68 02030670 3e7d6301 74bd2f9b 607a1e95 b6620ba2 5d2a3248 
   *
   * AURORA-256M(M1):
   * 46c5dba6 cfdc333b 7cfb4242 8fe59345 a0882acb c10c5694 9c248501 b156c457 
   *
   *---------------------------------------------------------------------------
   * M2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
   *
   * AURORA-224(M2):
   * 05874948 064d42ca e0ffa686 45034160 8d571731 f9581ca8 b8ea1890 
   *
   * AURORA-256(M2):
   * 21621069 e64ec45a eccf140a d881c684 44c30081 32a3b2d0 e9a1d961 d2dc034f 
   *
   * AURORA-384(M2):
   * f16bb878 ddee85ef 51994078 61aeee1c b23c63fb 6498f38d fbecf41e cf24805f
   * 8b28f018 656610f1 26ad1400 0a3f3ab6 
   *
   * AURORA-512(M2):
   * cbf432c3 01103535 f0cf0027 efe2b0c6 2046414e 6128ec83 bbd0bccf 7425f908
   * a5061438 6da57647 8f91cd42 1f4a0015 7b2fa527 d81328e7 76be3262 7352ef0c 
   *
   * AURORA-224M(M2):
   * 587879d0 6eebb1da 87b6de94 06e0dbdf 24e5fbad d98bc0dd 1257ad26 
   *
   * AURORA-256M(M2):
   * 3c3353d9 67d30005 de02cae6 e3b1a205 11e3b3a8 3d9048ee 5694df40 2bdc9588 
   *
   *---------------------------------------------------------------------------
   * M3 = 'a' x 1000000
   *
   * AURORA-224(M3):
   * 7977bc32 b66d7b05 6b215153 1545668d 5f3d1c6c 42a48334 5ab31f70 
   *
   * AURORA-256(M3):
   * ec8cede6 3fd1bd3b c6de6702 b6ed25e8 d80f5efa b5433912 446aaefc db026b5f 
   *
   * AURORA-384(M3):
   * c18722f8 d9e0fe10 de818d07 e8b66734 c23532ee 7d1d9968 18f60ab0 3950b416
   * cb89c086 8263eb84 3b4264d1 44c2180d 
   *
   * AURORA-512(M3):
   * 577e573e d9bfbc31 a80bcea8 2d1e4441 89d31fe0 7cda57d3 a2c8ad00 9800feae
   * 431e456b 85184399 5c12c5e6 6a7f7272 55880d11 375f08a1 4841fb96 86d390e4 
   *
   * AURORA-224M(M3):
   * c78f12a4 308821ab 3d312fdb 9dff6408 5496a44e a1aeebd5 a734166c 
   *
   * AURORA-256M(M3):
   * cd97a51f 79cb722a c2c33a46 62502b10 a13565b4 1f662699 11b9b438 f9fe81fb 
   */

  /* M1 */
  Hash(224, msg1, (sizeof(msg1) - 1) * 8, hashval);
  printf("AURORA-224  (msg1): "); BytePut(hashval, 28);

  Hash(256, msg1, (sizeof(msg1) - 1) * 8, hashval);
  printf("AURORA-256  (msg1): "); BytePut(hashval, 32);

  Hash(384, msg1, (sizeof(msg1) - 1) * 8, hashval);
  printf("AURORA-384  (msg1): "); BytePut(hashval, 48);

  Hash(512, msg1, (sizeof(msg1) - 1) * 8, hashval);
  printf("AURORA-512  (msg1): "); BytePut(hashval, 64);

  HashMcr(224, msg1, (sizeof(msg1) - 1) * 8, hashval);
  printf("AURORA-224M (msg1): "); BytePut(hashval, 28);

  HashMcr(256, msg1, (sizeof(msg1) - 1) * 8, hashval);
  printf("AURORA-256M (msg1): "); BytePut(hashval, 32);

  /* M2 */
  Hash(224, msg2, (sizeof(msg2) - 1) * 8, hashval);
  printf("AURORA-224  (msg2): "); BytePut(hashval, 28);

  Hash(256, msg2, (sizeof(msg2) - 1) * 8, hashval);
  printf("AURORA-256  (msg2): "); BytePut(hashval, 32);

  Hash(384, msg2, (sizeof(msg2) - 1) * 8, hashval);
  printf("AURORA-384  (msg2): "); BytePut(hashval, 48);

  Hash(512, msg2, (sizeof(msg2) - 1) * 8, hashval);
  printf("AURORA-512  (msg2): "); BytePut(hashval, 64);

  HashMcr(224, msg2, (sizeof(msg2) - 1) * 8, hashval);
  printf("AURORA-224M (msg2): "); BytePut(hashval, 28);

  HashMcr(256, msg2, (sizeof(msg2) - 1) * 8, hashval);
  printf("AURORA-256M (msg2): "); BytePut(hashval, 32);

  /* M3 */
  Init(&state, 224);
  for(i = 0; i < 1000000 / sizeof(msg3); i++){
    Update(&state, msg3, sizeof(msg3) * 8);
  }
  Final(&state, hashval);
  printf("AURORA-224  (msg3): "); BytePut(hashval, 28);  

  Init(&state, 256);
  for(i = 0; i < 1000000 / sizeof(msg3); i++){
    Update(&state, msg3, sizeof(msg3) * 8);
  }
  Final(&state, hashval);
  printf("AURORA-256  (msg3): "); BytePut(hashval, 32);  

  Init(&state, 384);
  for(i = 0; i < 1000000 / sizeof(msg3); i++){
    Update(&state, msg3, sizeof(msg3) * 8);
  }
  Final(&state, hashval);
  printf("AURORA-384  (msg3): "); BytePut(hashval, 48);  

  Init(&state, 512);
  for(i = 0; i < 1000000 / sizeof(msg3); i++){
    Update(&state, msg3, sizeof(msg3) * 8);
  }
  Final(&state, hashval);
  printf("AURORA-512  (msg3): "); BytePut(hashval, 64);  

  InitMcr(&state, 224);
  for(i = 0; i < 1000000 / sizeof(msg3); i++){
    Update(&state, msg3, sizeof(msg3) * 8);
  }
  Final(&state, hashval);
  printf("AURORA-224M (msg3): "); BytePut(hashval, 28);  

  InitMcr(&state, 256);
  for(i = 0; i < 1000000 / sizeof(msg3); i++){
    Update(&state, msg3, sizeof(msg3) * 8);
  }
  Final(&state, hashval);
  printf("AURORA-256M (msg3): "); BytePut(hashval, 32);  
}

int main(void)
{
  AuroraSample();

  return 0;
}

#endif /* _AURORA_TEST */



/* end of file */

