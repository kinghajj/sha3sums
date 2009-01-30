///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PROJECT : Arirang family
//
// DATE    : 2008.10.23
//
///////////////////////////////////////////////////////////////////////////////////////////////////
//
// FILE  : Arirang_OP32.h
//
// NOTES : Optimized code of Arirang family
// 
//         Based on 32-bit platform (4 32-bit S-box and 16 32-bit S-box version)
//
///////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Macro

// Define the Endianness
#undef BIG_ENDIAN
#undef LITTLE_ENDIAN

// Edit by Sam Fredrickson: use brg_endian.h to find system endianness.
#include "brg_endian.h"

#if PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN
#define USER_BIG_ENDIAN
#endif

#if PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN
#define USER_LITTLE_ENDIAN
#endif
////////////////////////////////////////////////////////////////////////////////

#if defined(USER_BIG_ENDIAN)
	#define BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
	#define LITTLE_ENDIAN
#else
	#if 0
		#define BIG_ENDIAN
	#elif defined(_MSC_VER)
		#define LITTLE_ENDIAN
	#else
		#error
	#endif
#endif

// Left and rigth rotation
#if defined(_MSC_VER)
	#define ROTL_DWORD(x, n) _lrotl((x), (n))
	#define ROTR_DWORD(x, n) _lrotr((x), (n))
#else
	#define ROTL_DWORD(x, n) ( (DWORD)((x) << (n)) | (DWORD)((x) >> (32-(n))) )
	#define ROTR_DWORD(x, n) ( (DWORD)((x) >> (n)) | (DWORD)((x) << (32-(n))) )
#endif

#define ROTL_DWORD1(x1, x2, n) ( (DWORD)((x1) << (n)) | (DWORD)((x2) >> (32-(n))) )
#define ROTL_DWORD2(x1, x2, n) ( (DWORD)((x2) << (n)) | (DWORD)((x1) >> (32-(n))) )

#define ROTR_DWORD1(x1, x2, n) ( (DWORD)((x1) >> (n)) | (DWORD)((x2) << (32-(n))) )
#define ROTR_DWORD2(x1, x2, n) ( (DWORD)((x2) >> (n)) | (DWORD)((x1) << (32-(n))) );

// Reverse the byte order of DWORD and WORD.
#define ENDIAN_REVERSE_DWORD(dwS)	( (ROTL_DWORD((dwS),  8) & 0x00ff00ff) | (ROTL_DWORD((dwS), 24) & 0xff00ff00) )

// Move DWORD type to BYTE type and BYTE type to DWORD type
#if defined(BIG_ENDIAN)
	#define BIG_B2D(B, D)		D = *(DWORD *)(B)
	#define BIG_D2B(D, B)		*(DWORD *)(B) = (DWORD)(D)
	#define LITTLE_B2D(B, D)	D = ENDIAN_REVERSE_DWORD(*(DWORD *)(B))
	#define LITTLE_D2B(D, B)	*(DWORD *)(B) = ENDIAN_REVERSE_DWORD(D)
#elif defined(LITTLE_ENDIAN)
	#define BIG_B2D(B, D)		D = ENDIAN_REVERSE_DWORD(*(DWORD *)(B))
	#define BIG_D2B(D, B)		*(DWORD *)(B) = ENDIAN_REVERSE_DWORD(D)
	#define LITTLE_B2D(B, D)	D = *(DWORD *)(B)
	#define LITTLE_D2B(D, B)	*(DWORD *)(B) = (DWORD)(D)
#endif


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Definition

#define ARIRANG224_BLOCK_LEN	64
#define ARIRANG224_DIGEST_LEN	28

#define ARIRANG256_BLOCK_LEN	64
#define ARIRANG256_DIGEST_LEN	32

#define ARIRANG384_BLOCK_LEN	128
#define ARIRANG384_DIGEST_LEN	48

#define ARIRANG512_BLOCK_LEN	128
#define ARIRANG512_DIGEST_LEN	64


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Datatype

typedef unsigned char BYTE;				//  8-bit data type

typedef unsigned char BitSequence;		//  8-bit data type

typedef unsigned short int WORD;		// 16-bit data type

typedef unsigned int DWORD;				// 32-bit data type

typedef unsigned long long QWORD;		// 64-bit data type

typedef unsigned long long DataLength;	// 64-bit data type


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Error

typedef enum {SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2} HashReturn;


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Structure

typedef struct {

	// Hash length
	int hashbitlen;
	
	// Counter
	DWORD counter[4];

	// Count
	DWORD count[4];

	// Message block
	BYTE block[ARIRANG512_BLOCK_LEN];

	// Working variables
	DWORD workingvar[16];

	// hash block length
	DWORD blocklen;

	// bit_length % 7
	DWORD remainderbit;


} hashState;


///////////////////////////////////////////////////////////////////////////////////////////////////
//
// Function

void gen_tabs(void);

HashReturn Init(hashState *state, int hashbitlen);

HashReturn Update(hashState *state, const BitSequence *data, DWORD* databitlen);

HashReturn Final(hashState *state, BYTE *hashval);

HashReturn Hash(int hashbitlen, const BitSequence *data, DWORD *databitlen, BitSequence *hashval);
