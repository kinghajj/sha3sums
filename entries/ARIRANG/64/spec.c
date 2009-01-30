///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PROJECT : ARIRANG family(ARIRANG-224,ARIRANG-256,ARIRANG-384,ARIRANG-512)
//
// DATE    : 2008.10.23
//
///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FILE  : ARIRANG_OP64.c
//
// NOTES : Optimized code of ARIRANG family
// 
//         Based on 64-bit platform (4 32-bit S-box and 8 8-bit S-box version)
//
///////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>

#include <memory.h>

#include "SHA3api_ref.h"


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Macro

#undef SS
#undef SSS

#define SS(x,n)			ROTL_DWORD(x,n)
#define SSS(x,n)		ROTL_QWORD(x,n)



///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Constant


static const DWORD K256[16] = {0x517cc1b7, 0x76517cc1, 0xbd76517c, 0x2dbd7651,
							   0x272dbd76, 0xcb272dbd, 0x90cb272d, 0x0a90cb27,
							   0xec0a90cb, 0x5bec0a90, 0x9a5bec0a, 0xe69a5bec,
							   0xb7e69a5b, 0xc1b7e69a, 0x7cc1b7e6, 0x517cc1b7};

static const QWORD K512[16] = {0x517cc1b727220a94, 0x2db6517cc1b72722, 0xe6952db6517cc1b7, 0x90cbe6952db6517c, 
								  0x7cca90cbe6952db6, 0xcb237cca90cbe695, 0x765ecb237cca90cb, 0xec01765ecb237cca, 
								  0xb7e9ec01765ecb23, 0xbd7db7e9ec01765e, 0x9a5fbd7db7e9ec01, 0x5be89a5fbd7db7e9, 
								  0x0a945be89a5fbd7d, 0x27220a945be89a5f, 0xc1b727220a945be8, 0x517cc1b727220a94};


DWORD	MDS4[4][256];
QWORD	MDS8[8][256];
BYTE	pow_tab[256];
BYTE	log_tab[256];
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
	DWORD i,t;
	QWORD s;
    BYTE p, q;
	DWORD temp2, temp4, temp8;
 
	/* log and power tables for GF(2**8) finite field with  */
    /* 0x011b as modular polynomial - the simplest primitive */
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

        t = ((DWORD)ff_mult(2, p)) | ((DWORD)p <<  8) | ((DWORD)p << 16) | ((DWORD)ff_mult(3, p) << 24);
        
        MDS4[0][i] = t;			MDS4[1][i] = SS(t,  8);	MDS4[2][i] = SS(t, 16);	MDS4[3][i] = SS(t, 24);
       		
		temp2=ff_mult(2,p);
		temp4=ff_mult(2,temp2);
		temp8=ff_mult(2,temp4);
		
        s = ((QWORD)p) | ((QWORD)p <<  8) | ((QWORD)temp4 << 16) | ((QWORD)p << 24) | ((QWORD)temp8 << 32 ) | ((QWORD)(temp8^p) <<  40) | ((QWORD)(temp8^temp2) << 48) | ((QWORD)(temp2) << 56);
		        
        MDS8[0][i] = s;				
		MDS8[1][i] = SSS(s,  8);	
		MDS8[2][i] = SSS(s, 16);	
		MDS8[3][i] = SSS(s, 24);	
		MDS8[4][i] = SSS(s, 32);				
		MDS8[5][i] = SSS(s, 40);	
		MDS8[6][i] = SSS(s, 48);	
		MDS8[7][i] = SSS(s, 56);	
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
#define Step512(A, B, C, D, E, F, G, H, M1, M2){							\
	A ^= M1;																\
	E ^= M2;																\
	temp1 =  MDS8[0][byte(A,0)] ^ MDS8[1][byte(A,1)] ^						\
			 MDS8[2][byte(A,2)] ^ MDS8[3][byte(A,3)] ^						\
			 MDS8[4][byte(A,4)] ^ MDS8[5][byte(A,5)] ^						\
			 MDS8[6][byte(A,6)] ^ MDS8[7][byte(A,7)] ;						\
	temp2 =  MDS8[0][byte(E,0)] ^ MDS8[1][byte(E,1)] ^						\
			 MDS8[2][byte(E,2)] ^ MDS8[3][byte(E,3)] ^						\
			 MDS8[4][byte(E,4)] ^ MDS8[5][byte(E,5)] ^						\
			 MDS8[6][byte(E,6)] ^ MDS8[7][byte(E,7)] ;						\
	B ^= temp1;																\
	C ^= SSS(temp1, 29);													\
	D ^= SSS(temp1, 41);													\
	F ^= temp2;																\
	G ^= SSS(temp2, 53);													\
	H ^= SSS(temp2, 13);													\
}


#define COUNT512() {state->counter[0]++; if(state->counter[0] == 0)	state->counter[1]++;}
#define COUNT256() {state->counter[0]++;}

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
	state->workingvar[0] ^= ((DWORD*)state->counter)[1];
	state->workingvar[4] ^= ((DWORD*)state->counter)[0];

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
	QWORD	R[8], W[32], temp1, temp2;
	int i;

	#if defined(BIG_ENDIAN)
		#define GetData(x) x
	#else
		#define GetData(x) ENDIAN_REVERSE_DWORD(x)
	#endif

	// Message Scheduling
	for (i = 0; i < 16; i++)
		W[i] = (QWORD)(GetData(((DWORD*)state->block)[2*i+1])) | ((QWORD)(GetData(((DWORD*)state->block)[2*i])) << 32); 
											
	W[16] = SSS((W[ 9] ^ W[11] ^ W[13] ^ W[15] ^ K512[ 0]), 11);
	W[17] = SSS((W[ 8] ^ W[10] ^ W[12] ^ W[14] ^ K512[ 1]), 23);
	W[18] = SSS((W[ 1] ^ W[ 3] ^ W[ 5] ^ W[ 7] ^ K512[ 2]), 37);
	W[19] = SSS((W[ 0] ^ W[ 2] ^ W[ 4] ^ W[ 6] ^ K512[ 3]), 59);

	W[20] = SSS((W[14] ^ W[ 4] ^ W[10] ^ W[ 0] ^ K512[ 4]), 11);
	W[21] = SSS((W[11] ^ W[ 1] ^ W[ 7] ^ W[13] ^ K512[ 5]), 23);
	W[22] = SSS((W[ 6] ^ W[12] ^ W[ 2] ^ W[ 8] ^ K512[ 6]), 37);
	W[23] = SSS((W[ 3] ^ W[ 9] ^ W[15] ^ W[ 5] ^ K512[ 7]), 59);

	W[24] = SSS((W[13] ^ W[15] ^ W[ 1] ^ W[ 3] ^ K512[ 8]), 11);
	W[25] = SSS((W[ 4] ^ W[ 6] ^ W[ 8] ^ W[10] ^ K512[ 9]), 23);
	W[26] = SSS((W[ 5] ^ W[ 7] ^ W[ 9] ^ W[11] ^ K512[10]), 37);
	W[27] = SSS((W[12] ^ W[14] ^ W[ 0] ^ W[ 2] ^ K512[11]), 59);

	W[28] = SSS((W[10] ^ W[ 0] ^ W[ 6] ^ W[12] ^ K512[12]), 11);
	W[29] = SSS((W[15] ^ W[ 5] ^ W[11] ^ W[ 1] ^ K512[13]), 23);
	W[30] = SSS((W[ 2] ^ W[ 8] ^ W[14] ^ W[ 4] ^ K512[14]), 37);
	W[31] = SSS((W[ 7] ^ W[13] ^ W[ 3] ^ W[ 9] ^ K512[15]), 59);
																												

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
	Step512(R[0], R[1], R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[16], W[17]);
	Step512(R[7], R[0], R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[ 0], W[ 1]);
	Step512(R[6], R[7], R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[ 2], W[ 3]);
	Step512(R[5], R[6], R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[ 4], W[ 5]);
	Step512(R[4], R[5], R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[ 6], W[ 7]);

	Step512(R[3], R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[18], W[19]);
	Step512(R[2], R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[ 8], W[ 9]);
	Step512(R[1], R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[10], W[11]);
	Step512(R[0], R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[12], W[13]);
	Step512(R[7], R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[14], W[15]);

	// 2 Round
	Step512(R[6], R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[20], W[21]);
	Step512(R[5], R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[ 3], W[ 6]);
	Step512(R[4], R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[ 9], W[12]);
	Step512(R[3], R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[15], W[ 2]);
	Step512(R[2], R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[ 5], W[ 8]);

	Step512(R[1], R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[22], W[23]);
	Step512(R[0], R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[11], W[14]);
	Step512(R[7], R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[ 1], W[ 4]);
	Step512(R[6], R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[ 7], W[10]);
	Step512(R[5], R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[13], W[ 0]);

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
	Step512(R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[24], W[25]);
	Step512(R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[12], W[ 5]);
	Step512(R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[14], W[ 7]);
	Step512(R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[ 0], W[ 9]);
	Step512(R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[ 2], W[11]);

	Step512(R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[26], W[27]);
	Step512(R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[ 4], W[13]);
	Step512(R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[ 6], W[15]);
	Step512(R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[ 8], W[ 1]);
	Step512(R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[10], W[ 3]);

	// 4 Round
	Step512(R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[28], W[29]);
	Step512(R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[ 7], W[ 2]);
	Step512(R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7], W[13], W[ 8]);
	Step512(R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6], W[ 3], W[14]);
	Step512(R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4] ,R[5], W[ 9], W[ 4]);

	Step512(R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3] ,R[4], W[30], W[31]);
	Step512(R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2] ,R[3], W[15], W[10]);
	Step512(R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1] ,R[2], W[ 5], W[ 0]);
	Step512(R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0] ,R[1], W[11], W[ 6]);
	Step512(R[1] ,R[2] ,R[3] ,R[4] ,R[5] ,R[6] ,R[7] ,R[0], W[ 1], W[12]);

	// Feedforward_2
	state->workingvar[0] ^= R[0];
	state->workingvar[1] ^= R[1];
	state->workingvar[2] ^= R[2];
	state->workingvar[3] ^= R[3];
	state->workingvar[4] ^= R[4];
	state->workingvar[5] ^= R[5];
	state->workingvar[6] ^= R[6];
	state->workingvar[7] ^= R[7];
	
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
	state->counter[0] = state->counter[1] = 0;	
	
	// Initialize the Data Length
	state->count[0] = state->count[1] = 0;

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
		state->workingvar[0]=0xcbbb9d5dc1059ed8ULL;
		state->workingvar[1]=0x629a292a367cd507ULL;
		state->workingvar[2]=0x9159015a3070dd17ULL;	
		state->workingvar[3]=0x152fecd8f70e5939ULL;
		state->workingvar[4]=0x67332667ffc00b31ULL;
		state->workingvar[5]=0x8eb44a8768581511ULL;
		state->workingvar[6]=0xdb0c2e0d64f98fa7ULL;
		state->workingvar[7]=0x47b5481dbefa4fa4ULL;
		state->blocklen=ARIRANG512_BLOCK_LEN;
	
	}													
	else if(hashbitlen == 512){									
		state->workingvar[0]=0x6a09e667f3bcc908ULL;
		state->workingvar[1]=0xbb67ae8584caa73bULL;
		state->workingvar[2]=0x3c6ef372fe94f82bULL;
		state->workingvar[3]=0xa54ff53a5f1d36f1ULL;
		state->workingvar[4]=0x510e527fade682d1ULL;
		state->workingvar[5]=0x9b05688c2b3e6c1fULL;
		state->workingvar[6]=0x1f83d9abfb41bd6bULL;
		state->workingvar[7]=0x5be0cd19137e2179ULL;
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

HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen)
{
	DWORD RemainedLen, PartLen;
	QWORD databytelen, temp;

	databytelen = ( databitlen >> 3) + (state->remainderbit != 0); 
	
	// Compute the number of hashed bytes mod ARIRANG_BLOCK_LEN
	RemainedLen = (state->count[0] >> 3) % state->blocklen;

	// Compute the number of bytes that can be filled up
	PartLen = state->blocklen - RemainedLen;

	// Update count (number of toatl data bits)
	temp = state->count[0] + (databytelen << 3);
	if( temp  < state->count[0] )	state->count[1]++;		
	state->count[0]=temp;
	
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
	DWORD i, dwIndex;
	DWORD temp=(state->blocklen >> 3);
	QWORD count[2];

	// Padding the message
	if(state->remainderbit){
		count[0] = state->count[0] + state->remainderbit - 8;
		count[1] = state->count[1];
		dwIndex = ((count[0] + (state->blocklen<<3) ) >> 3) % state->blocklen;
		state->block[dwIndex] &= 0xff-(1<<(8-state->remainderbit))+1;		
		state->block[dwIndex++] ^= 0x80>>(state->remainderbit);
	}
	else{
		count[0] = state->count[0];
		count[1] = state->count[1];		
		dwIndex = (count[0] >> 3) % state->blocklen;		
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
	count[0] = ENDIAN_REVERSE_DWORD(((DWORD*)count)[1])| ((QWORD)(ENDIAN_REVERSE_DWORD(((DWORD*)count)[0])) << 32);
	count[1] = ENDIAN_REVERSE_DWORD(((DWORD*)count)[3])| ((QWORD)(ENDIAN_REVERSE_DWORD(((DWORD*)count)[2])) << 32);
#endif
	
	// Fixed counter value for the last message block
	if(state->hashbitlen > 257){
		((QWORD *)state->block)[state->blocklen/8-2] = count[1];
		((QWORD *)state->block)[state->blocklen/8-1] = count[0];
		state->counter[1]=0xb7e151628aed2a6aULL;
		state->counter[0]=0xbf7158809cf4f3c7ULL;
	}
	else{
		((QWORD *)state->block)[state->blocklen/8-1] = count[0];
		state->counter[0]=0xb7e151628aed2a6aULL;	
	}
	
	if(state->hashbitlen <257) Arirang_Compression256(state);
	else Arirang_Compression512(state);


	if(state->hashbitlen <257)
		for (i = 0; i < (state->hashbitlen >> 3); i += 4)	BIG_D2B((state->workingvar)[(i*2) / 8], &(hashval[i]));
	else
		for (i = 0; i < (state->hashbitlen >> 3); i += 8)	BIG_Q2B((state->workingvar)[i / 8], &(hashval[i]));

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
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength *databitlen, BitSequence *hashval){

	hashState State;
	BitSequence *UpdatedData;	
	DataLength UpdatedDataLengthbit=0x100000000;
	int i,j;
	
	UpdatedData=data;
	State.remainderbit = databitlen[0] & 7;

	Init(&State, hashbitlen);

	i=0,j=0;
	while((j < databitlen[1]) && (i < ((DWORD*)databitlen)[1])){
		Update(&State, UpdatedData, UpdatedDataLengthbit);
		UpdatedData+=0x2000000;
		i++; if(i != 0); else j++;
	}	
	UpdatedDataLengthbit = databitlen[0] & 0xffffffff; 
	Update(&State, UpdatedData, UpdatedDataLengthbit);

	Final(&State, hashval);

	return SUCCESS;	
}
