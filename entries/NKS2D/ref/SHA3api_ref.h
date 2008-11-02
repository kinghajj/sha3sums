/** 
 * @mainpage 
 * ANSI C Cryptographic API Profile for SHA-3 Candidate Algorithm Submissions.
 *
 * Defines required functions for NIST SHA3 hash contest, as well as
 * data structures and extended functions required by NKS 2D Cellular Automata
 * hash. 
 * @author Geoffrey Park
 * @date 2008
 */

#ifndef SHA3API_REF_H
#define SHA3API_REF_H

#include <stdint.h>

typedef int64_t DataLength;
typedef unsigned char BitSequence;

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;

/**
 * @brief Hash state structure. Holds all intermediate state during hash generation.
*/
typedef struct _HashStreamState {
	// stream specifc algorithm parameters:
	int generationRule;
	int dataOverlap;
	int nGenerationsPerBlock;
	// current state:
	int parity;
	int blocksProcessed;
	unsigned char *cellPlane[2];
} HashStreamState;

typedef struct _HashState {
	// algorithm parameters:
	int hashbitlen;
	int width;
	int height;
	DataLength databitlen;
	int nStreams;
	// current state:
	int curStream;
	int cellPlaneSz;
	unsigned char *tempData;
	DataLength tempSz;
	int optflags;
	HashStreamState hashState[8];
} HashState, hashState;


HashReturn HashEx(int hashbitlen,const BitSequence *data,DataLength databitlen,BitSequence *hashval,int nStreams,int nGenerations,int *pRules,float *pOverlap);
HashReturn InitEx(HashState *pHashState, int hashbitlen, int nStreams,int nGenerations, int *pRules, float *pOverlap, int optflags);

HashReturn Hash( int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);
HashReturn Update(HashState *pstate, const BitSequence *data, DataLength databitlen);
HashReturn Init(HashState *pstate, int hashbitlen);
HashReturn Final(HashState *pstate, BitSequence *hashval);

#endif
