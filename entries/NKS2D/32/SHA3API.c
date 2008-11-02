//---------------NKS 2D Cellular Automata Hash-----------------------
// SHA3API.c 
//
// Copyright © 2007,2008,  Geoffrey Park
//-------------------------------------------------------------------
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "SHA3api_ref.h"
#include "NKS2DCAhash.h"

/**
 * @brief Extended version of Init().
 *
 * Allows specification of alternative cellular automaton rule, optimization flags.
 */
HashReturn
InitEx(HashState *pHashState, int hashbitlen, int nStreams, int nGenerations, int *pRules, float *pOverlap, int optflags)
{	HashStreamState *pstate;
	HashReturn result = SUCCESS;
	int nS,ng,w,h,maxdim,cellPlaneSz,blockSz;
	pHashState->width = w = 16*(int)(ceil(sqrt((float)hashbitlen)/16));
	pHashState->height = h = (int)ceil(hashbitlen/(float)w);
	pHashState->hashbitlen = hashbitlen;
	pHashState->optflags = optflags;
	pHashState->nStreams = nStreams;
	pHashState->curStream = 0;
	cellPlaneSz = (w/8)*h;
	pHashState->scratchPlanes =	(BitSequence *) calloc(8*cellPlaneSz, 1);
	pHashState->cellPlaneSz = cellPlaneSz;
	maxdim = h > w ? h : w;
	blockSz = pHashState->cellPlaneSz;

	for(nS = 0; nS < nStreams; nS++)
	{
		int rule, parity;
		parity = 0;
		pstate = &pHashState->hashState[nS];
		pstate->dataOverlap = (int)(pOverlap[nS]*blockSz);
		pstate->nGenerationsPerBlock = nGenerations;
		pstate->blocksProcessed = 0;

		pstate->cellPlane[0] =	(BitSequence *) calloc(cellPlaneSz*2,1);
		pstate->cellPlane[1]  =	(BitSequence *) calloc(cellPlaneSz*2,1);
		pstate->tableCache = NULL;
		rule = pRules[nS];

		if(rule == 0){
			rule = HEX_NEIGHBORS | 8604;
		}

		pstate->generationRule = rule;

		pstate->cellPlane[0][0] = 1 + nS; // Make sure each stream gets a different seed
		pHashState->databitlen = 0;

		for(ng=0;ng<maxdim;ng++) {
			nextGen(pstate->cellPlane[parity], pstate->cellPlane[parity ^ 1],
						pHashState->scratchPlanes, pHashState->width, pHashState->height, 
						pstate->generationRule, pHashState->optflags, &(pstate->tableCache));
			parity ^= 1;
		}
		pstate->parity = parity;
	}

	pHashState->tempData = (BitSequence *) calloc(cellPlaneSz*2, 1);
	pHashState->tempSz = 0;

	return result;
}

/**
 * @brief Initializes a hashState with the intended hash length of this particular instantiation.
 *
 * Data independent setup is also performed.
 */
HashReturn
Init(HashState *pstate, int hashbitlen)
{
	int rules224[4] = { HEX_NEIGHBORS | 8604 };
	float overlap224[4] = {.25F };
	int rules256[4] = { HEX_NEIGHBORS | 8604, HEX_NEIGHBORS | 4558};
	float overlap256[4] = {.25F, .25F };
	int rules384[4] = { HEX_NEIGHBORS | 8604, HEX_NEIGHBORS | 4558, HEX_NEIGHBORS | 7473 };
	float overlap384[4] = {.334F, .334F, .334F };
	int rules512[4] = { HEX_NEIGHBORS | 8604, HEX_NEIGHBORS | 4558, HEX_NEIGHBORS | 7473 };
	float overlap512[4] = {0.0F, 1.0F, 1.0F };

	int nRules;
	int *rules;
	float *overlap;

	switch(hashbitlen){
		case 224:
			rules = rules224;
			overlap = overlap224;
			nRules = 1;
			break;
		case 256:
			rules = rules256;
			overlap = overlap256;
			nRules = 2;
			break;
		case 384:
			rules = rules384;
			overlap = overlap384;
			nRules = 3;
			break;
		case 512:
			rules = rules512;
			overlap = overlap512;
			nRules = 3;
			break;
		default:
			rules = rules512;
			overlap = overlap512;
			nRules = 3;
			break;
	}

	InitEx(pstate, hashbitlen, nRules, 1, rules, overlap, LARGEDATA );
	return SUCCESS;
}

/**
 * @brief Process the supplied data.
 */
HashReturn
Update(HashState *pHashState, const BitSequence *data, DataLength databitlen)
{
	HashStreamState *pstate;
	DataLength nD;
	DataLength len;
	const BitSequence *pData;
	int count = 0;
	int rule = 0;
	int blockSz;
//puts("\nUpdate\n");
	blockSz = pHashState->cellPlaneSz;

	len = (databitlen + 7)/8;
	pHashState->databitlen += databitlen;
	pData = data;
	
	
	do {
		int i;
		nD = blockSz - pHashState->tempSz;
		nD = nD < len ? nD : len;
		memcpy(pHashState->tempData+pHashState->tempSz,pData,(size_t)nD);
		pHashState->tempSz += nD;

		if(pHashState->tempSz < blockSz){
			// still haven't got enough to hash:
			return SUCCESS;
		}
		len -= nD;
		pData += nD;

		pstate = &pHashState->hashState[pHashState->curStream];
		//printf("\nCurStream=%d\n",pHashState->curStream);
		for(i=0;i<pstate->nGenerationsPerBlock;i++){
			int k;
			//puts("");
			//printf("[%d]",pHashState->curStream);
			for(k=0;k<blockSz;k++){
				pstate->cellPlane[pstate->parity][k] ^= pHashState->tempData[k]; 
				//printf("%02x",pHashState->tempData[k]);
				//printf("%02x",pstate->cellPlane[pstate->parity][k]);
			}
			nextGen( pstate->cellPlane[pstate->parity],
					 pstate->cellPlane[pstate->parity ^ 1],
					 pHashState->scratchPlanes,
					 pHashState->width, pHashState->height, 
					 pstate->generationRule,
					 pHashState->optflags, &(pstate->tableCache));
			pstate->parity ^= 1;
		}

		memcpy(pHashState->tempData,pHashState->tempData + blockSz - pstate->dataOverlap,pstate->dataOverlap);
		pHashState->tempSz = pstate->dataOverlap;

		pHashState->curStream++;
		pHashState->curStream = pHashState->curStream % pHashState->nStreams;
	} while (len > 0);

	return SUCCESS;
}

/**
 * @brief Perform post processing and return the final hash value.
 */

HashReturn
Final(HashState *pHashState, BitSequence *hashval)
{
	HashStreamState *pstate;
	int ng,nS,maxdim,blockSz;
	unsigned char *pData;
	int hashByteLen = (pHashState->hashbitlen+7)/8;
	pstate = pHashState->hashState;
	maxdim = pHashState->height > pHashState->width ? pHashState->height : pHashState->width;
	blockSz = pHashState->cellPlaneSz;
//puts("\nFinal\n");

	Update(pHashState,(BitSequence *)&(pHashState->databitlen), 64);

	pData = pHashState->tempData;

	for(nS = 0; nS < pHashState->nStreams; nS++){

		pstate = &pHashState->hashState[pHashState->curStream];
		//printf("\nnS=%d Blocks=%d ",pHashState->curStream,pstate->blocksProcessed);

		if(pData){
			int k;
			for(k=0;k<pHashState->tempSz;k++){
				pstate->cellPlane[pstate->parity][k] ^= pData[k]; 
				//printf("%02x",pHashState->tempData[k]);
			}
		}
		for(ng = 0; ng < maxdim; ng++)
		{
			nextGen( pstate->cellPlane[pstate->parity],
					 pstate->cellPlane[pstate->parity ^ 1],
					 pHashState->scratchPlanes,
					 pHashState->width, pHashState->height, 
					 pstate->generationRule,
					 pHashState->optflags, &(pstate->tableCache));
			pstate->parity ^= 1;
		}

		if(pHashState->tempSz > blockSz -  pstate->dataOverlap){
			int nD = (int)(pHashState->tempSz - blockSz + pstate->dataOverlap);
			memcpy(pHashState->tempData,pHashState->tempData + blockSz - pstate->dataOverlap,nD);
			pHashState->tempSz = nD;
		} else {
			pHashState->tempSz = 0;
		}

		pHashState->curStream++;
		pHashState->curStream = pHashState->curStream % pHashState->nStreams;

	}
	
	//memcpy(hashval,pstate->cellPlane[pstate->parity],pstate->hashbitlen/8);

	memset(hashval,0,hashByteLen);
	for(nS = 0; nS < pHashState->nStreams; nS++){
		int idx0, idx1;
		pstate = &pHashState->hashState[nS];
		idx1 = hashByteLen/2;
		for(idx0=0,idx1 = hashByteLen/2;idx0<hashByteLen;idx0++){
			hashval[idx0] ^= pstate->cellPlane[0][idx0];
			hashval[idx0] ^= pstate->cellPlane[1][idx1];
			idx1 = (++idx1) % hashByteLen;
		}
		free(pstate->cellPlane[0]);
		free(pstate->cellPlane[1]);
		if(pstate->tableCache != NULL){
			free(pstate->tableCache);
		}

	}
	free(pHashState->scratchPlanes);
	free(pHashState->tempData);
	return SUCCESS;
}

/**
 * @brief Extended version of Hash().
 *
 * Allows specification of alternative cellular automaton rule.
 */
HashReturn HashEx(int hashbitlen,const BitSequence *data, DataLength databitlen, BitSequence *hashval, int nStreams, int nGenerations, int *pRules, float *pOverlap)
{
	HashReturn result = SUCCESS;
	HashState state;
	int optflags = 0;
	//DataLength lHashed;
	const BitSequence *pData;
	pData = data;
	optflags = (databitlen/8 > 140000) ? LARGEDATA : 0;

	result = InitEx(&state, hashbitlen, nStreams, nGenerations, pRules, pOverlap,  optflags );

	Update(&state, pData, databitlen);

	Final(&state,hashval);
	return SUCCESS;
}

/**
 * @brief Hash the supplied data and provide the resulting hash value.
 *
 * Uses default cellular automaton rule: HEX8604.
 */
HashReturn Hash( int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval)
{
	int rules224[4] = { HEX_NEIGHBORS | 8604 };
	float overlap224[4] = {.25F };
	int rules256[4] = { HEX_NEIGHBORS | 8604, HEX_NEIGHBORS | 4558};
	float overlap256[4] = {.25F, .25F };
	int rules384[4] = { HEX_NEIGHBORS | 8604, HEX_NEIGHBORS | 4558, HEX_NEIGHBORS | 7473 };
	float overlap384[4] = {.334F, .334F, .334F };
	int rules512[4] = { HEX_NEIGHBORS | 8604, HEX_NEIGHBORS | 4558, HEX_NEIGHBORS | 7473 };
	float overlap512[4] = {0.0F, 1.0F, 1.0F };

	int nRules;
	int *rules;
	float *overlap;

	switch(hashbitlen){
		case 224:
			rules = rules224;
			overlap = overlap224;
			nRules = 1;
			break;
		case 256:
			rules = rules256;
			overlap = overlap256;
			nRules = 2;
			break;
		case 384:
			rules = rules384;
			overlap = overlap384;
			nRules = 3;
			break;
		case 512:
			rules = rules512;
			overlap = overlap512;
			nRules = 3;
			break;
		default:
			rules = rules512;
			overlap = overlap512;
			nRules = 3;
			break;
	}

	return HashEx(hashbitlen, data, databitlen, hashval, nRules, 1, rules, overlap); 
}
