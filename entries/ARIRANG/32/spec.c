///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PROJECT : ARIRANG family(ARIRANG-224,ARIRANG-256,ARIRANG-384,ARIRANG-512)
//
// DATE    : 2008.10.23
//
///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FILE  : ARIRANG_OP32.c
//
// NOTES : Optimized code of ARIRANG family
// 
//         Based on 32-bit platform (with four 32-bit S-box and sixteen 32-bit S-box version)
//
///////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>

#include <memory.h>

#include "SHA3api_ref.h"


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Macro

#undef SS
#undef SS1
#undef SS2

#define SS(x,n)				ROTL_DWORD(x,n)
#define SS1(x1,x2,n)		ROTL_DWORD1(x1,x2,n)
#define SS2(x1,x2,n)		ROTL_DWORD2(x1,x2,n)


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Constant

static const DWORD K256[16] = {0x517cc1b7, 0x76517cc1, 0xbd76517c, 0x2dbd7651,
							   0x272dbd76, 0xcb272dbd, 0x90cb272d, 0x0a90cb27,
							   0xec0a90cb, 0x5bec0a90, 0x9a5bec0a, 0xe69a5bec,
							   0xb7e69a5b, 0xc1b7e69a, 0x7cc1b7e6, 0x517cc1b7};

static const DWORD K512[16][2] = {0x517cc1b7, 0x27220a94, 0x2db6517c, 0xc1b72722, 0xe6952db6, 0x517cc1b7, 0x90cbe695, 0x2db6517c, 
								  0x7cca90cb, 0xe6952db6, 0xcb237cca, 0x90cbe695, 0x765ecb23, 0x7cca90cb, 0xec01765e, 0xcb237cca, 
								  0xb7e9ec01, 0x765ecb23, 0xbd7db7e9, 0xec01765e, 0x9a5fbd7d, 0xb7e9ec01, 0x5be89a5f, 0xbd7db7e9, 
								  0x0a945be8, 0x9a5fbd7d, 0x27220a94, 0x5be89a5f, 0xc1b72722, 0x0a945be8, 0x517cc1b7, 0x27220a94};


DWORD	MDS4[4][256];
DWORD	MDS8[8][256][2];
BYTE	sbx[256];

#define ff_mult(a, b)	(a && b ? pow_tab[(log_tab[a] + log_tab[b]) % 255] : 0)
#define byte(x, n)		((BYTE)((x) >> (8 * n)))

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : gen_tabs
//
// DESCRIPTION    : Generate the s-box table and field multiplication table
//
// PARAMETERS     : void
//                  
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////
void gen_tabs(void)
{   
	DWORD i, t[2];
    BYTE p, q;
	BYTE	pow_tab[256];
	BYTE	log_tab[256];
	DWORD temp2, temp4, temp8;
 
	/* log and power tables for GF(2^8) finite field with  */
    /* 0x011b as modular polynomial - the simplest prmitive */
    /* root is 0x03, used here to generate the tables       */

    for (i = 0, p = 1; i < 256; ++i)
    {
        pow_tab[i] = (BYTE)p;
		log_tab[p] = (BYTE)i;

        p = p ^ (p << 1) ^ (p & 0x80 ? 0x01b : 0);
    }

    /* note that the affine byte transformation matrix in   */
    /* ARIRANG specification is in big endian format with  */
    /* bit 0 as the most significant bit. In the remainder  */
    /* of the specification the bits are numbered from the  */
    /* least significant end of a byte.                     */

    for (i = 0; i < 256; ++i)
    {   
        p = (i ? pow_tab[255 - log_tab[i]] : 0); q = p; 
        q = (q >> 7) | (q << 1); p ^= q; 
        q = (q >> 7) | (q << 1); p ^= q; 
        q = (q >> 7) | (q << 1); p ^= q; 
        q = (q >> 7) | (q << 1); p ^= q ^ 0x63; 
        sbx[i] = p;
    }

    for (i = 0; i < 256; ++i)
    {
        p = sbx[i];

        t[0] = ((DWORD)ff_mult(2, p)) | ((DWORD)p <<  8) | ((DWORD)p << 16) | ((DWORD)ff_mult(3, p) << 24);
        
        MDS4[0][i] = t[0];			MDS4[1][i] = SS(t[0],  8);	MDS4[2][i] = SS(t[0], 16);	MDS4[3][i] = SS(t[0], 24);
       		
		temp2=ff_mult(2,p);
		temp4=ff_mult(2,temp2);
		temp8=ff_mult(2,temp4);

		t[0] = ((DWORD)temp8) | ((DWORD)(temp8^p) <<  8) | ((DWORD)(temp8^temp2) << 16) | ((DWORD)(temp2) << 24);
        t[1] = ((DWORD)p) | ((DWORD)p <<  8) | ((DWORD)temp4 << 16) | ((DWORD)p << 24);
		        
        MDS8[0][i][1] = t[0];				MDS8[0][i][0] = t[1];
		MDS8[1][i][1] = SS1(t[0],t[1],  8);	MDS8[1][i][0] = SS2(t[0],t[1],  8);
		MDS8[2][i][1] = SS1(t[0],t[1], 16);	MDS8[2][i][0] = SS2(t[0],t[1], 16);	
		MDS8[3][i][1] = SS1(t[0],t[1], 24);	MDS8[3][i][0] = SS2(t[0],t[1], 24);
		MDS8[4][i][1] = t[1];				MDS8[4][i][0] = t[0];
		MDS8[5][i][1] = SS2(t[0],t[1],  8);	MDS8[5][i][0] = SS1(t[0],t[1],  8);
		MDS8[6][i][1] = SS2(t[0],t[1], 16);	MDS8[6][i][0] = SS1(t[0],t[1], 16);
		MDS8[7][i][1] = SS2(t[0],t[1], 24);	MDS8[7][i][0] = SS1(t[0],t[1], 24);
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : step256
//
// DESCRIPTION    : Step function of ARIRANG-224 and ARIRANG-256
//
// PARAMETERS     : A,B,C,D,E,F,G,H  - working variables
//                  M1,M2 - message block
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////
#define Step256(A, B, C, D, E, F, G, H, M1, M2)					\
	A ^= M1;													\
	E ^= M2;													\
	temp1 =  MDS4[0][byte(A,0)] ^ MDS4[1][byte(A,1)] ^			\
			 MDS4[2][byte(A,2)] ^ MDS4[3][byte(A,3)] ;			\
	temp2 =  MDS4[0][byte(E,0)] ^ MDS4[1][byte(E,1)] ^			\
			 MDS4[2][byte(E,2)] ^ MDS4[3][byte(E,3)] ;			\
	B ^= temp1;													\
	C ^= SS(temp1, 13);											\
	D ^= SS(temp1, 23);											\
	F ^= temp2;													\
	G ^= SS(temp2, 29);											\
	H ^= SS(temp2, 7);											\

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : step512
//
// DESCRIPTION    : Step function of ARIRANG-384 and Arirang-512
//
// PARAMETERS     : A,B,C,D,E,F,G,H  - working variables
//                  M1,M2 - message block
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////
#define Step512(A1, A2, B1, B2, C1, C2, D1, D2, E1, E2, F1, F2, G1, G2, H1, H2, M11, M12, M21, M22){	\
	A1 ^= M11;		A2 ^= M12;																			\
	E1 ^= M21;		E2 ^= M22;																			\
	temp[0] =  MDS8[0][byte(A2,0)][1] ^ MDS8[1][byte(A2,1)][1] ^										\
			   MDS8[2][byte(A2,2)][1] ^ MDS8[3][byte(A2,3)][1] ^										\
			   MDS8[4][byte(A1,0)][1] ^ MDS8[5][byte(A1,1)][1] ^										\
			   MDS8[6][byte(A1,2)][1] ^ MDS8[7][byte(A1,3)][1] ;										\
	temp[1] =  MDS8[0][byte(A2,0)][0] ^ MDS8[1][byte(A2,1)][0] ^										\
			   MDS8[2][byte(A2,2)][0] ^ MDS8[3][byte(A2,3)][0] ^										\
			   MDS8[4][byte(A1,0)][0] ^ MDS8[5][byte(A1,1)][0] ^										\
			   MDS8[6][byte(A1,2)][0] ^ MDS8[7][byte(A1,3)][0] ;										\
	temp[2] =  MDS8[0][byte(E2,0)][1] ^ MDS8[1][byte(E2,1)][1] ^										\
			   MDS8[2][byte(E2,2)][1] ^ MDS8[3][byte(E2,3)][1] ^										\
			   MDS8[4][byte(E1,0)][1] ^ MDS8[5][byte(E1,1)][1] ^										\
			   MDS8[6][byte(E1,2)][1] ^ MDS8[7][byte(E1,3)][1] ;										\
	temp[3] =  MDS8[0][byte(E2,0)][0] ^ MDS8[1][byte(E2,1)][0] ^										\
			   MDS8[2][byte(E2,2)][0] ^ MDS8[3][byte(E2,3)][0] ^										\
			   MDS8[4][byte(E1,0)][0] ^ MDS8[5][byte(E1,1)][0] ^										\
			   MDS8[6][byte(E1,2)][0] ^ MDS8[7][byte(E1,3)][0] ;										\
	B1 ^= temp[0];					B2 ^= temp[1];														\
	C1 ^= SS1(temp[0],temp[1], 29);	C2 ^= SS2(temp[0],temp[1], 29);										\
	D1 ^= SS2(temp[0],temp[1],  9);	D2 ^= SS1(temp[0],temp[1],  9);										\
	F1 ^= temp[2];					F2 ^= temp[3];														\
	G1 ^= SS2(temp[2],temp[3], 21);	G2 ^= SS1(temp[2],temp[3], 21);										\
	H1 ^= SS1(temp[2],temp[3], 13);	H2 ^= SS2(temp[2],temp[3], 13);										\
}



#define COUNT256(){												\
	      state->counter[0]++; if(state->counter[0]!=0x00);		\
	else {state->counter[1]++;}}								\

#define COUNT512(){												\
	      state->counter[0]++; if(state->counter[0]!=0x00);		\
	else {state->counter[1]++; if(state->counter[1]!=0x00);		\
	else {state->counter[2]++; if(state->counter[2]!=0x00);		\
	else {state->counter[3]++; }}}}								\


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Arirang_Compression256
//
// DESCRIPTION    : Counter addition and compression function of Arirang-224 and ARIRANG-256
//
// PARAMETERS     : state - a structure that holds the hashState information
//
// RETURNS        : void
//
///////////////////////////////////////////////////////////////////////////////////////////////////

void Arirang_Compression256(hashState *state)
{
	DWORD	R[8], W[32], temp1, temp2;
	int i;

	#if defined(BIG_ENDIAN)
		#define GetData(x) x
	#else
		#define GetData(x) ENDIAN_REVERSE_DWORD(x)
	#endif

	// Message Scheduling
	for (i = 0; i < 16; i++)
		W[i] = GetData(((DWORD*)state->block)[i]);

	W[16] = SS((W[ 9] ^ W[11] ^ W[13] ^ W[15] ^ K256[ 0]),  5);
	W[17] = SS((W[ 8] ^ W[10] ^ W[12] ^ W[14] ^ K256[ 1]), 11);
	W[18] = SS((W[ 1] ^ W[ 3] ^ W[ 5] ^ W[ 7] ^ K256[ 2]), 19);
	W[19] = SS((W[ 0] ^ W[ 2] ^ W[ 4] ^ W[ 6] ^ K256[ 3]), 31);

	W[20] = SS((W[14] ^ W[ 4] ^ W[10] ^ W[ 0] ^ K256[ 4]),  5);
	W[21] = SS((W[11] ^ W[ 1] ^ W[ 7] ^ W[13] ^ K256[ 5]), 11);
	W[22] = SS((W[ 6] ^ W[12] ^ W[ 2] ^ W[ 8] ^ K256[ 6]), 19);
	W[23] = SS((W[ 3] ^ W[ 9] ^ W[15] ^ W[ 5] ^ K256[ 7]), 31);

	W[24] = SS((W[13] ^ W[15] ^ W[ 1] ^ W[ 3] ^ K256[ 8]),  5);
	W[25] = SS((W[ 4] ^ W[ 6] ^ W[ 8] ^ W[10] ^ K256[ 9]), 11);
	W[26] = SS((W[ 5] ^ W[ 7] ^ W[ 9] ^ W[11] ^ K256[10]), 19);
	W[27] = SS((W[12] ^ W[14] ^ W[ 0] ^ W[ 2] ^ K256[11]), 31);

	W[28] = SS((W[10] ^ W[ 0] ^ W[ 6] ^ W[12] ^ K256[12]),  5);
	W[29] = SS((W[15] ^ W[ 5] ^ W[11] ^ W[ 1] ^ K256[13]), 11);
	W[30] = SS((W[ 2] ^ W[ 8] ^ W[14] ^ W[ 4] ^ K256[14]), 19);
	W[31] = SS((W[ 7] ^ W[13] ^ W[ 3] ^ W[ 9] ^ K256[15]), 31);

	// Counter Addition
	state->workingvar[0] ^= state->counter[1];
	state->workingvar[4] ^= state->counter[0];

	// Initialize Register
	R[0] = state->workingvar[0];
	R[1] = state->workingvar[1];
	R[2] = state->workingvar[2];
	R[3] = state->workingvar[3];
	R[4] = state->workingvar[4];
	R[5] = state->workingvar[5];
	R[6] = state->workingvar[6];
	R[7] = state->workingvar[7];
	
	// 1 Round
	Step256(R[0], R[1], R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[16], W[17]);
	Step256(R[7], R[0], R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[ 0], W[ 1]);
	Step256(R[6], R[7], R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[ 2], W[ 3]);
	Step256(R[5], R[6], R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[ 4], W[ 5]);
	Step256(R[4], R[5], R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[ 6], W[ 7]);

	Step256(R[3], R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[18], W[19]);
	Step256(R[2], R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[ 8], W[ 9]);
	Step256(R[1], R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[10], W[11]);
	Step256(R[0], R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[12], W[13]);
	Step256(R[7], R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[14], W[15]);

	// 2 Round
	Step256(R[6], R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[20], W[21]);
	Step256(R[5], R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[ 3], W[ 6]);
	Step256(R[4], R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[ 9], W[12]);
	Step256(R[3], R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[15], W[ 2]);
	Step256(R[2], R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[ 5], W[ 8]);

	Step256(R[1], R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[22], W[23]);
	Step256(R[0], R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[11], W[14]);
	Step256(R[7], R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[ 1], W[ 4]);
	Step256(R[6], R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[ 7], W[10]);
	Step256(R[5], R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[13], W[ 0]);

	// Feedforward_1
	R[0] ^= state->workingvar[4];
	R[1] ^= state->workingvar[5];
	R[2] ^= state->workingvar[6];
	R[3] ^= state->workingvar[7];
	R[4] ^= state->workingvar[0];
	R[5] ^= state->workingvar[1];
	R[6] ^= state->workingvar[2];
	R[7] ^= state->workingvar[3];

	// 3 Round
	Step256(R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[24], W[25]);
	Step256(R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[12], W[ 5]);
	Step256(R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[14], W[ 7]);
	Step256(R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[ 0], W[ 9]);
	Step256(R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[ 2], W[11]);

	Step256(R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[26], W[27]);
	Step256(R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[ 4], W[13]);
	Step256(R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[ 6], W[15]);
	Step256(R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[ 8], W[ 1]);
	Step256(R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[10], W[ 3]);

	// 4 Round
	Step256(R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[28], W[29]);
	Step256(R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[ 7], W[ 2]);
	Step256(R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[13], W[ 8]);
	Step256(R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[ 3], W[14]);
	Step256(R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[ 9], W[ 4]);

	Step256(R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[30], W[31]);
	Step256(R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[15], W[10]);
	Step256(R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[ 5], W[ 0]);
	Step256(R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[11], W[ 6]);
	Step256(R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[ 1], W[12]);

	// Feedforward_2
	state->workingvar[0] ^= R[0];
	state->workingvar[1] ^= R[1];
	state->workingvar[2] ^= R[2];
	state->workingvar[3] ^= R[3];
	state->workingvar[4] ^= R[4];
	state->workingvar[5] ^= R[5];
	state->workingvar[6] ^= R[6];
	state->workingvar[7] ^= R[7];

	COUNT256();
}

void Arirang_Compression512(hashState *state)
{
	DWORD	R[16], W[64], temp[4];
	int i;

	#if defined(BIG_ENDIAN)
		#define GetData(x) x
	#else
		#define GetData(x) ENDIAN_REVERSE_DWORD(x)
	#endif

	// Message Scheduling
	for (i = 0; i < 32; i++)
		W[i] = GetData(((DWORD*)state->block)[i]);
									
	temp[0]=(W[18]^W[22]^W[26]^W[30]^K512[ 0][0]);	temp[1]=(W[19]^W[23]^W[27]^W[31]^K512[ 0][1]);
	W[32]=SS1(temp[0], temp[1], 11);				W[33]=SS2(temp[0], temp[1], 11);							
	temp[0]=(W[16]^W[20]^W[24]^W[28]^K512[ 1][0]);  temp[1]=(W[17]^W[21]^W[25]^W[29]^K512[ 1][1]);	
	W[34]=SS1(temp[0], temp[1], 23);				W[35]=SS2(temp[0], temp[1], 23);							
	temp[0]=(W[ 2]^W[ 6]^W[10]^W[14]^K512[ 2][0]);	temp[1]=(W[ 3]^W[ 7]^W[11]^W[15]^K512[ 2][1]);
	W[36]=SS2(temp[0], temp[1], 5);					W[37]=SS1(temp[0], temp[1], 5);								
	temp[0]=(W[ 0]^W[ 4]^W[ 8]^W[12]^K512[ 3][0]);	temp[1]=(W[ 1]^W[ 5]^W[ 9]^W[13]^K512[ 3][1]);
	W[38]=SS2(temp[0], temp[1], 27);				W[39]=SS1(temp[0], temp[1], 27);							
	temp[0]=(W[28]^W[ 8]^W[20]^W[ 0]^K512[ 4][0]);	temp[1]=(W[29]^W[ 9]^W[21]^W[ 1]^K512[ 4][1]);
	W[40]=SS1(temp[0], temp[1], 11);				W[41]=SS2(temp[0], temp[1], 11);							
	temp[0]=(W[22]^W[ 2]^W[14]^W[26]^K512[ 5][0]);	temp[1]=(W[23]^W[ 3]^W[15]^W[27]^K512[ 5][1]);
	W[42]=SS1(temp[0], temp[1], 23);				W[43]=SS2(temp[0], temp[1], 23);							
	temp[0]=(W[12]^W[24]^W[ 4]^W[16]^K512[ 6][0]);	temp[1]=(W[13]^W[25]^W[ 5]^W[17]^K512[ 6][1]);
	W[44]=SS2(temp[0], temp[1], 5);					W[45]=SS1(temp[0], temp[1], 5);								
	temp[0]=(W[ 6]^W[18]^W[30]^W[10]^K512[ 7][0]);	temp[1]=(W[ 7]^W[19]^W[31]^W[11]^K512[ 7][1]);
	W[46]=SS2(temp[0], temp[1], 27);				W[47]=SS1(temp[0], temp[1], 27);							
	temp[0]=(W[26]^W[30]^W[ 2]^W[ 6]^K512[ 8][0]);	temp[1]=(W[27]^W[31]^W[ 3]^W[ 7]^K512[ 8][1]);
	W[48]=SS1(temp[0], temp[1], 11);				W[49]=SS2(temp[0], temp[1], 11);							
	temp[0]=(W[ 8]^W[12]^W[16]^W[20]^K512[ 9][0]);	temp[1]=(W[ 9]^W[13]^W[17]^W[21]^K512[ 9][1]);
	W[50]=SS1(temp[0], temp[1], 23);				W[51]=SS2(temp[0], temp[1], 23);							
	temp[0]=(W[10]^W[14]^W[18]^W[22]^K512[10][0]);	temp[1]=(W[11]^W[15]^W[19]^W[23]^K512[10][1]);
	W[52]=SS2(temp[0], temp[1], 5);					W[53]=SS1(temp[0], temp[1], 5);								
	temp[0]=(W[24]^W[28]^W[ 0]^W[ 4]^K512[11][0]);	temp[1]=(W[25]^W[29]^W[ 1]^W[ 5]^K512[11][1]);
	W[54]=SS2(temp[0], temp[1], 27);				W[55]=SS1(temp[0], temp[1], 27);							
	temp[0]=(W[20]^W[ 0]^W[12]^W[24]^K512[12][0]);	temp[1]=(W[21]^W[ 1]^W[13]^W[25]^K512[12][1]);
	W[56]=SS1(temp[0], temp[1], 11);				W[57]=SS2(temp[0], temp[1], 11);							
	temp[0]=(W[30]^W[10]^W[22]^W[ 2]^K512[13][0]);	temp[1]=(W[31]^W[11]^W[23]^W[ 3]^K512[13][1]);
	W[58]=SS1(temp[0], temp[1], 23);				W[59]=SS2(temp[0], temp[1], 23);							
	temp[0]=(W[ 4]^W[16]^W[28]^W[ 8]^K512[14][0]);	temp[1]=(W[ 5]^W[17]^W[29]^W[ 9]^K512[14][1]);
	W[60]=SS2(temp[0], temp[1], 5);					W[61]=SS1(temp[0], temp[1], 5);								
	temp[0]=(W[14]^W[26]^W[ 6]^W[18]^K512[15][0]);	temp[1]=(W[15]^W[27]^W[ 7]^W[19]^K512[15][1]);
	W[62]=SS2(temp[0], temp[1], 27);				W[63]=SS1(temp[0], temp[1], 27);																														

	// Counter Addition
	state->workingvar[0] ^= state->counter[3];
	state->workingvar[1] ^= state->counter[2];
	state->workingvar[8] ^= state->counter[1];
	state->workingvar[9] ^= state->counter[0];

	// Initialize Register
	R[ 0] = state->workingvar[ 0];	R[ 1] = state->workingvar[ 1];
	R[ 2] = state->workingvar[ 2];	R[ 3] = state->workingvar[ 3];
	R[ 4] = state->workingvar[ 4];	R[ 5] = state->workingvar[ 5];
	R[ 6] = state->workingvar[ 6];	R[ 7] = state->workingvar[ 7];
	R[ 8] = state->workingvar[ 8];	R[ 9] = state->workingvar[ 9];
	R[10] = state->workingvar[10];	R[11] = state->workingvar[11];
	R[12] = state->workingvar[12];	R[13] = state->workingvar[13];
	R[14] = state->workingvar[14];	R[15] = state->workingvar[15];
	
	// 1 Round
	Step512(R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], W[32], W[33], W[34], W[35]);         
	Step512(R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], W[ 0], W[ 1], W[ 2], W[ 3]);
	Step512(R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], W[ 4], W[ 5], W[ 6], W[ 7]);
	Step512(R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], W[ 8], W[ 9], W[10], W[11]);
	Step512(R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], W[12], W[13], W[14], W[15]);
	Step512(R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], W[36], W[37], W[38], W[39]);
	Step512(R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], W[16], W[17], W[18], W[19]);
	Step512(R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], W[20], W[21], W[22], W[23]);
	Step512(R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], W[24], W[25], W[26], W[27]);
	Step512(R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], W[28], W[29], W[30], W[31]);
              
	// 2 round
	Step512(R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], W[40], W[41], W[42], W[43]);
	Step512(R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], W[ 6], W[ 7], W[12], W[13]);
	Step512(R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], W[18], W[19], W[24], W[25]);
	Step512(R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], W[30], W[31], W[ 4], W[ 5]);
	Step512(R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], W[10], W[11], W[16], W[17]);
	Step512(R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], W[44], W[45], W[46], W[47]);
	Step512(R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], W[22], W[23], W[28], W[29]);
	Step512(R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], W[ 2], W[ 3], W[ 8], W[ 9]);
	Step512(R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], W[14], W[15], W[20], W[21]);
	Step512(R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], W[26], W[27], W[ 0], W[ 1]);
	


	// Feedforward_1
	R[ 0] ^= state->workingvar[ 8];	R[ 1] ^= state->workingvar[ 9];
	R[ 2] ^= state->workingvar[10];	R[ 3] ^= state->workingvar[11];
	R[ 4] ^= state->workingvar[12];	R[ 5] ^= state->workingvar[13];
	R[ 6] ^= state->workingvar[14];	R[ 7] ^= state->workingvar[15];
	R[ 8] ^= state->workingvar[ 0];	R[ 9] ^= state->workingvar[ 1];
	R[10] ^= state->workingvar[ 2];	R[11] ^= state->workingvar[ 3];
	R[12] ^= state->workingvar[ 4];	R[13] ^= state->workingvar[ 5];
	R[14] ^= state->workingvar[ 6];	R[15] ^= state->workingvar[ 7];

	// 3 Round
	Step512(R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], W[48], W[49], W[50], W[51]);
	Step512(R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], W[24], W[25], W[10], W[11]);
	Step512(R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], W[28], W[29], W[14], W[15]);
	Step512(R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], W[ 0], W[ 1], W[18], W[19]);
	Step512(R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], W[ 4], W[ 5], W[22], W[23]);
	Step512(R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], W[52], W[53], W[54], W[55]);
	Step512(R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], W[ 8], W[ 9], W[26], W[27]);
	Step512(R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], W[12], W[13], W[30], W[31]);
	Step512(R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], W[16], W[17], W[ 2], W[ 3]);
	Step512(R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], W[20], W[21], W[ 6], W[ 7]);
    
	// 4 round
	Step512(R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], W[56], W[57], W[58], W[59]);
	Step512(R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], W[14], W[15], W[ 4], W[ 5]);
	Step512(R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], W[26], W[27], W[16], W[17]);
	Step512(R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], W[ 6], W[ 7], W[28], W[29]);
	Step512(R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], W[18], W[19], W[ 8], W[ 9]);
	Step512(R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], W[60], W[61], W[62], W[63]);
	Step512(R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], W[30], W[31], W[20], W[21]);
	Step512(R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], R[ 4], R[ 5], W[10], W[11], W[ 0], W[ 1]);
	Step512(R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], R[ 2], R[ 3], W[22], W[23], W[12], W[13]);
	Step512(R[ 2], R[ 3], R[ 4], R[ 5], R[ 6], R[ 7], R[ 8], R[ 9], R[10], R[11], R[12], R[13], R[14], R[15], R[ 0], R[ 1], W[ 2], W[ 3], W[24], W[25]);
	

	// Feedforward_2
	state->workingvar[ 0] ^= R[ 0];	state->workingvar[ 1] ^= R[ 1];
	state->workingvar[ 2] ^= R[ 2];	state->workingvar[ 3] ^= R[ 3];
	state->workingvar[ 4] ^= R[ 4];	state->workingvar[ 5] ^= R[ 5];
	state->workingvar[ 6] ^= R[ 6];	state->workingvar[ 7] ^= R[ 7];
	state->workingvar[ 8] ^= R[ 8];	state->workingvar[ 9] ^= R[ 9];
	state->workingvar[10] ^= R[10];	state->workingvar[11] ^= R[11];
	state->workingvar[12] ^= R[12];	state->workingvar[13] ^= R[13];
	state->workingvar[14] ^= R[14];	state->workingvar[15] ^= R[15];
	
	COUNT512();														
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Init
//
// DESCRIPTION    : Initialize a hashState with the intended hash length of particular instantiation.
//
// PARAMETERS     : state - a structure that holds the hashState information
//                  hashbitlen - an integer value that indicates the length of the hash output in bits
//
// RETURNS        : SUCCESS - on success
//                  BAD_HASHLEN - hashbitlen is invalid
//
///////////////////////////////////////////////////////////////////////////////////////////////////

HashReturn Init(hashState *state, int hashbitlen)
{
	if ((hashbitlen != 224) && (hashbitlen != 256) && (hashbitlen != 384) && (hashbitlen != 512))
		return BAD_HASHLEN;

	// Setting the Hash Length
	state->hashbitlen = hashbitlen;
	
	// Setting the Counter Values
	state->counter[0] = state->counter[1] = state->counter[2] = state->counter[3]= 0;	
	
	// Initialize the Data Length
	state->count[0] = state->count[1] = state->count[2] = state->count[3] = 0;

	// Setting the Initial Hash Value
	if(state->hashbitlen == 224){
		state->workingvar[0] = 0xcbbb9d5d;
		state->workingvar[1] = 0x629a292a;
		state->workingvar[2] = 0x9159015a;
		state->workingvar[3] = 0x152fecd8;
		state->workingvar[4] = 0x67332667;
		state->workingvar[5] = 0x8eb44a87;
		state->workingvar[6] = 0xdb0c2e0d;
		state->workingvar[7] = 0x47b5481d;
		state->blocklen=ARIRANG256_BLOCK_LEN;
	}
		
	else if(state->hashbitlen == 256){
		state->workingvar[0] = 0x6a09e667;
		state->workingvar[1] = 0xbb67ae85;
		state->workingvar[2] = 0x3c6ef372;
		state->workingvar[3] = 0xa54ff53a;
		state->workingvar[4] = 0x510e527f;
		state->workingvar[5] = 0x9b05688c;
		state->workingvar[6] = 0x1f83d9ab;
		state->workingvar[7] = 0x5be0cd19;
		state->blocklen=ARIRANG256_BLOCK_LEN;
	
	}
	else if(hashbitlen == 384){	
		state->workingvar[ 0]=0xcbbb9d5d; state->workingvar[ 1]=0xc1059ed8;
		state->workingvar[ 2]=0x629a292a; state->workingvar[ 3]=0x367cd507;
		state->workingvar[ 4]=0x9159015a; state->workingvar[ 5]=0x3070dd17;	
		state->workingvar[ 6]=0x152fecd8; state->workingvar[ 7]=0xf70e5939;
		state->workingvar[ 8]=0x67332667; state->workingvar[ 9]=0xffc00b31;
		state->workingvar[10]=0x8eb44a87; state->workingvar[11]=0x68581511;
		state->workingvar[12]=0xdb0c2e0d; state->workingvar[13]=0x64f98fa7;
		state->workingvar[14]=0x47b5481d; state->workingvar[15]=0xbefa4fa4;
		state->blocklen=ARIRANG512_BLOCK_LEN;
	
	}													
	else if(hashbitlen == 512){									
		state->workingvar[ 0]=0x6a09e667; state->workingvar[ 1]=0xf3bcc908;
		state->workingvar[ 2]=0xbb67ae85; state->workingvar[ 3]=0x84caa73b;
		state->workingvar[ 4]=0x3c6ef372; state->workingvar[ 5]=0xfe94f82b;
		state->workingvar[ 6]=0xa54ff53a; state->workingvar[ 7]=0x5f1d36f1;
		state->workingvar[ 8]=0x510e527f; state->workingvar[ 9]=0xade682d1;
		state->workingvar[10]=0x9b05688c; state->workingvar[11]=0x2b3e6c1f;
		state->workingvar[12]=0x1f83d9ab; state->workingvar[13]=0xfb41bd6b;
		state->workingvar[14]=0x5be0cd19; state->workingvar[15]=0x137e2179;
		state->blocklen=ARIRANG512_BLOCK_LEN;		
	}
	return SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Update
//
// DESCRIPTION    : Process the supplied data.
//
// PARAMETERS     : state - a structure that holds the hashState information
//                  data - the data to be hashed
//                  Databitlen - the length, in bits, of the data to be hashed
//
// RETURNS        : SUCCESS - on success
//
///////////////////////////////////////////////////////////////////////////////////////////////////

HashReturn Update(hashState *state, const BitSequence *data, DWORD* databitlen)
{
	DWORD RemainedLen, PartLen, temp;
	DWORD databytelen;

	if(databitlen[1] == 1)
		databytelen = 0x20000000;
	else
		databytelen = ( databitlen[0] >> 3) + (state->remainderbit != 0); 
	
	// Compute the number of hashed bytes mod ARIRANG_BLOCK_LEN
	RemainedLen = (state->count[0] >> 3) % state->blocklen;

	// Compute the number of bytes that can be filled up
	PartLen = state->blocklen - RemainedLen;

	// Update count (number of toatl data bits)
	temp = state->count[0] + (databytelen << 3);
	if( temp  < state->count[0] ){
		state->count[ 1]++; if(state->count[ 1] != 0x00);
		else {state->count[ 2]++; if(state->count[ 2] != 0x00); 
		else {state->count[ 3]++;}}
	}
	state->count[0]=temp;
	
	temp = state->count[1] + (databytelen >> 29);
	if( temp  < state->count[1] ){
		state->count[ 2]++; if(state->count[ 1] != 0x00);
		else {state->count[ 3]++;}
	}
	state->count[1]=temp;

	if ((databytelen > PartLen) || ((databytelen == PartLen) && (state->remainderbit == 0)) ) {
		memcpy(state->block + RemainedLen, data, (int)PartLen);
		if(state->hashbitlen <257) Arirang_Compression256(state);
		else Arirang_Compression512(state);

		data += PartLen;
		databytelen -= PartLen;
		RemainedLen = 0;

		while( (databytelen > state->blocklen) || ((databytelen == state->blocklen) && (state->remainderbit == 0)) ) {
			memcpy((BYTE *)state->block, data, (int)state->blocklen);
			if(state->hashbitlen <257) Arirang_Compression256(state);
			else Arirang_Compression512(state);

			data += state->blocklen;
			databytelen -= state->blocklen;
		}
	}

	//	Buffer remaining input
	memcpy((BYTE *)state->block + RemainedLen, data, (int)databytelen);

	return SUCCESS;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Final
//
// DESCRIPTION    : Perform any post processing and ouput filtering required and return the final 
//                  hash value.
//
// PARAMETERS     : state - a structure that holds the hashState information
//                  hashval - the storage for the final hash value to be returned
//
// RETURNS        : SUCCESS - on success
//
///////////////////////////////////////////////////////////////////////////////////////////////////

HashReturn Final(hashState *state, BYTE *hashval)
{
	DWORD i, dwIndex, Count[4];
	DWORD temp=(state->blocklen >> 3);

	// Padding the message
	if(state->remainderbit){
		Count[0] = state->count[0] + state->remainderbit - 8;
		Count[1] = state->count[1];
		Count[2] = state->count[2];
		Count[3] = state->count[3];

		dwIndex = ((Count[0] + (state->blocklen<<3) ) >> 3) % state->blocklen;
		state->block[dwIndex] &= 0xff-(1<<(8-state->remainderbit))+1;		
		state->block[dwIndex++] ^= 0x80>>(state->remainderbit);
	}
	else{
		Count[0] = state->count[0];
		Count[1] = state->count[1];
		Count[2] = state->count[2];
		Count[3] = state->count[3];
		dwIndex = (Count[0] >> 3) % state->blocklen;		
		state->block[dwIndex++] = 0x80;	
	}
		
	if (dwIndex > (state->blocklen - temp)){
		memset((BYTE *)state->block + dwIndex, 0, (int)(state->blocklen - dwIndex));
		if(state->hashbitlen <257) Arirang_Compression256(state);
		else Arirang_Compression512(state);

		memset((BYTE *)state->block, 0, (int)state->blocklen - temp);
	}
	else
		memset((BYTE *)state->block + dwIndex, 0, (int)(state->blocklen - dwIndex - temp));

#if defined(LITTLE_ENDIAN)
	Count[0] = ENDIAN_REVERSE_DWORD(Count[0]);
	Count[1] = ENDIAN_REVERSE_DWORD(Count[1]);
	Count[2] = ENDIAN_REVERSE_DWORD(Count[2]);
	Count[3] = ENDIAN_REVERSE_DWORD(Count[3]);
#endif
	
	// Fixed counter value for the last message block
	if(state->hashbitlen > 257){
		((DWORD *)state->block)[state->blocklen/4-4] = Count[3];
		((DWORD *)state->block)[state->blocklen/4-3] = Count[2];
		((DWORD *)state->block)[state->blocklen/4-2] = Count[1];
		((DWORD *)state->block)[state->blocklen/4-1] = Count[0];
		state->counter[3]=0xb7e15162;	state->counter[2]=0x8aed2a6a;
		state->counter[1]=0xbf715880;	state->counter[0]=0x9cf4f3c7;
	}
	else{
		((DWORD *)state->block)[state->blocklen/4-2] = Count[1];
		((DWORD *)state->block)[state->blocklen/4-1] = Count[0];
		state->counter[1]=0xb7e15162;	state->counter[0]=0x8aed2a6a;	
	}
	
	if(state->hashbitlen <257) Arirang_Compression256(state);
	else Arirang_Compression512(state);

	for (i = 0; i < (state->hashbitlen >> 3); i += 4)
		BIG_D2B((state->workingvar)[i / 4], &(hashval[i]));

	return SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FUNCTION NAME  : Hash
//
// DESCRIPTION    : Hash the supplied data and provide the resulting hash value. 
//                  
//
// PARAMETERS     : state      - a structure that holds the hashState information
//                  data       - the data to be hashed
//                  databitlen - the length, in bits, of the data to be hashed
//                  hashval    - the storage for the final hash value to be returned
//
// RETURNS        : SUCCESS - on success
//
///////////////////////////////////////////////////////////////////////////////////////////////////
HashReturn Hash(int hashbitlen, const BitSequence *data, DWORD *databitlen, BitSequence *hashval){

	hashState State;
	BitSequence *UpdatedData;	
	DWORD UpdatedDataLengthbit[2]={0,1};
	int i,j,k;
	
	UpdatedData=data;
	State.remainderbit = databitlen[0] & 7;

	Init(&State, hashbitlen);

	i=0;j=0;k=0;
	while((i < databitlen[1]) || (j < databitlen[2]) || (k < databitlen[3]) ){
		Update(&State, UpdatedData, UpdatedDataLengthbit);
		UpdatedData+=0x20000000;
		i++; if(i != 0);
		else {j++;if(j != 0);
		else {k++;}}
	}
	UpdatedDataLengthbit[1] = 0;
	UpdatedDataLengthbit[0] = databitlen[0];
	Update(&State, UpdatedData, UpdatedDataLengthbit);

	Final(&State, hashval);

	return SUCCESS;	
}
