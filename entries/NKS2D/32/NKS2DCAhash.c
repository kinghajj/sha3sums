/**
 * @file NKS2DCAhash.c
 * @brief NKS 2D Cellular Automata Hash
 * 
 * Optimized C language version:
 * Implements 2D cellular automata generator for totalistic
 * generation rules as described in: 
 * "A New Kind of Science"
 * by Stephen Wolfram ISBN I-57955-008-8
 * [referred to below as 'NKS'] 
 * Optionally data can be mixed into each generation to influence the
 * generator output.
 * @author Copyright © 2007, 2008,  Geoffrey Park
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "SHA3api_ref.h"
#include "NKS2DCAhash.h"

/**
 * @brief shift a bit row left 1 bit, leftmost bit shifts in again on right.
 */
void rolLeft(unsigned char *dst, unsigned char *src, int size)
{
	unsigned char *pS, *pD, bit;
	pS = (unsigned char *)src + size - 1;
	pD = (unsigned char *)dst + size - 1;
	bit = (src[0] & 0x80) >> 7;
	for(;size > 0; size--){
		*pD = (*pS << 1) | bit;
		bit = (*pS & 0x80) >> 7;
		pD--;
		pS--;
	}
}

/**
 * @brief shift a bit row right 1 bit, rightmost bit shifts in again on left.
 */
void rolRight(unsigned char *dst, unsigned char *src, int size)
{
	unsigned char *pS, *pD, bit;
	pS = (unsigned char *)src;
	pD = (unsigned char *)dst;
	bit = (pS[size-1] & 1) << 7;
	for(;size > 0; size--){
		*pD = (*pS >> 1) | bit;
		bit = (*pS & 1) << 7;
		pD++;
		pS++;
	}
}

/**
 * @brief shift a bit row left 1 bit, leftmost bit is 'reflection' of bit to the right.
 */
void shiftLeftReflect(unsigned char *dst, unsigned char *src, int size)
{
	unsigned char *pS, *pD, bit;
	pS = (unsigned char *)src + size - 1;
	pD = (unsigned char *)dst + size - 1;
	bit = (*pS & 0x02) >> 1;
	for(;size > 0; size--){
		*pD = (*pS << 1) | bit;
		bit = (*pS & 0x80) >> 7;
		pD--;
		pS--;
	}
}

/**
 * @brief shift a bit row right 1 bit, rightmost  bit is 'reflection' of bit to the left.
 */
void shiftRightReflect(unsigned char *dst, unsigned char *src, int size)
{
	unsigned char *pS, *pD, bit;
	pS = (unsigned char *)src;
	pD = (unsigned char *)dst;
	bit = (*pS & 0x40) << 1;
	for(;size > 0; size--){
		*pD = (*pS >> 1) | bit;
		bit = (*pS & 1) << 7;
		pD++;
		pS++;
	}
}

#ifdef TOROID_TOPOLOGY
#define ShiftLeft rolLeft
#define ShiftRight rolRight
#else
#define ShiftLeft shiftLeftReflect
#define ShiftRight shiftRightReflect
#endif

/**
 * @brief Generates next plane using a 'rectangular' type cellular automata rule.
 *
 * Given a bitplane w by h in curBits, generates a new bitplane in nextBits, using a 
 * cellular automaton defined by rule, where rule uses the current pixel and it's
 * four neighbors in rectangular positions above, below, left, right.
 *
 * inrule defines a totalistic cellular automaton using the convention of NKS chapter 5,
 * where cells have 4 neighbors in "rectangular" positions e.g. above, below, left, right.
 */
void nextGenRect(BitSequence *curBits, 
				BitSequence *nextBits, BitSequence *temp,
				int w, int h,
				int inrule)
{
	unsigned char *src, *dst, *pT, *pB, *pL, *pR;
	unsigned long *plT, *plB, *plL, *plR;
	uint64_t *nT, *nB, *nL, *nR;
	uint64_t *lD, *lS;
	int ll;
	int r;
	int width = w;
	int stride = w/8;
	int plSz = stride*h;
	int nqw = (h*stride)/8;
	int rule = inrule;
	src = curBits;
	dst = nextBits;

	nT = plT = pT = temp;
	nB = plB = pB = temp + plSz;
	nL = plL = pL = temp + 2*plSz;
	nR = plR = pR = temp + 3*plSz;
#ifdef TOROID_TOPOLOGY
	memcpy(pT,src+(h-1)*stride,stride);
#else
	memcpy(pB,src + stride,stride);
#endif
	memcpy(pT,pB,stride);
	ShiftRight(pL,src,stride);
	ShiftLeft(pR,src,stride);
	pT += stride;
	pB += stride;
	pL += stride;
	pR += stride;
	src += stride;
	dst += stride;
	for( r=1; r<h-1;r++)
	{
		memcpy(pT,src - stride,stride);
		memcpy(pB,src + stride,stride);
		ShiftRight(pL,src,stride);
		ShiftLeft(pR,src,stride);
		pT += stride;
		pB += stride;
		pL += stride;
		pR += stride;
		src += stride;
		dst += stride;
	}
	memcpy(pT,src - stride,stride);
#ifdef TOROID_TOPOLOGY
	memcpy(pB,src-(h-1)*stride,stride);
#else
	memcpy(pB,pT,stride);
#endif
	ShiftRight(pL,src,stride);
	ShiftLeft(pR,src,stride);

	src = curBits;
	dst = nextBits;

	lS = (uint64_t *)src;
	lD = (uint64_t *)dst;

	for(ll = 0; ll < nqw; ll++)
	{
		uint64_t mask = 0x1111111111111111;
		uint64_t bm = 0x1;
		uint64_t nBits;
		int i,j;

		*lD = 0;
		for(j=0;j<4;j++)
		{
			nBits = 0;
			nBits += (*nT  >> j) & mask;
			nBits += (*nB  >> j) & mask;
			nBits += (*nL  >> j) & mask;
			nBits += (*nR  >> j) & mask;
			nBits <<= 1;
			nBits += (*lS  >> j) & mask;

			for(i=0;i<8;i++)
			{
				char *nbc = (char *) &nBits;
				char *dc = (char *) lD;
				int bt = (nbc[i] >> 4) & 0xf;
				int obit = ((rule >> bt) & 1);
				dc[i] |= (obit << (j+4));	

				bt = nbc[i] & 0xf;
				obit = ((rule >> bt) & 1);
				dc[i] |= (obit << j);				
			}
		}
		++lS;
		++lD;
		++nT;
		++nB;
		++nL;
		++nR;
	}
}

/**
 * @brief Generates next plane using a 'diagonal' type cellular automata rule.
 *
 * Given a bitplane w by h in curBits, generates a new bitplane in nextBits, using a 
 * cellular automaton defined by rule, where rule uses the current pixel and it's
 * four neighbors in rectangular positions above, below, left, right.
 *
 * inrule defines a totalistic cellular automaton using the convention of NKS chapter 5,
 * where cells have 4 neighbors in "diagonal" positions e.g. above-left, above-right, below-left, below-right
 */
void nextGenDiag(BitSequence *curBits, 
				BitSequence *nextBits, BitSequence *temp,
				int w, int h,
				int inrule)
{
	unsigned char *src, *dst, *pT, *pB, *pL, *pR;
	unsigned long *plT, *plB, *plL, *plR;
	uint64_t *nT, *nB, *nL, *nR;
	uint64_t *lD, *lS;
	int ll;
	int r;
	int width = w;
	int stride = w/8;
	int plSz = stride*h;
	int nqw = (h*stride)/8;
	int rule = inrule;
	src = curBits;
	dst = nextBits;

	nT = plT = pT = temp;
	nB = plB = pB = temp + plSz;
	nL = plL = pL = temp + 2*plSz;
	nR = plR = pR = temp + 3*plSz;

#ifdef TOROID_TOPOLOGY
	rolRight(pT,src+(h-1)*stride,stride);
	rolLeft(pR,src+(h-1)*stride,stride);
#else
	ShiftRight(pT,src + stride,stride);
	ShiftLeft(pR,src + stride,stride);
#endif
	memcpy(pL,pT,stride);
	memcpy(pB,pR,stride);

	pT += stride;
	pR += stride;
	pL += stride;
	pB += stride;
	src += stride;
	dst += stride;
	for( r=1; r<h-1;r++)
	{
		ShiftRight(pT,src - stride,stride);
		ShiftLeft(pR,src - stride,stride);
		ShiftRight(pL,src + stride,stride);
		ShiftLeft(pB,src + stride,stride);
		pT += stride;
		pR += stride;
		pL += stride;
		pB += stride;
		src += stride;
		dst += stride;
	}
	ShiftRight(pT,src - stride,stride);
	ShiftLeft(pR,src - stride,stride);

#ifdef TOROID_TOPOLOGY
	rolRight(pL,src - (h-1)*stride,stride);
	rolLeft(pB,src - (h-1)*stride,stride);
#else
	memcpy(pL,pT,stride);
	memcpy(pB,pR,stride);
#endif

	src = curBits;
	dst = nextBits;

	lS = (uint64_t *)src;
	lD = (uint64_t *)dst;

	for(ll = 0; ll < nqw; ll++)
	{
		uint64_t mask = 0x1111111111111111;
		uint64_t bm = 0x1;
		uint64_t nBits;
		int i,j;

		*lD = 0;
		for(j=0;j<4;j++)
		{
			nBits = 0;
			nBits += (*nT  >> j) & mask;
			nBits += (*nB  >> j) & mask;
			nBits += (*nL  >> j) & mask;
			nBits += (*nR  >> j) & mask;
			nBits <<= 1;
			nBits += (*lS  >> j) & mask;

			for(i=0;i<8;i++)
			{
				char *nbc = (char *) &nBits;
				char *dc = (char *) lD;
				int bt = (nbc[i] >> 4) & 0xf;
				int obit = ((rule >> bt) & 1);
				dc[i] |= (obit << (j+4));	

				bt = nbc[i] & 0xf;
				obit = ((rule >> bt) & 1);
				dc[i] |= (obit << j);				
			}
		}
		++lS;
		++lD;
		++nT;
		++nB;
		++nL;
		++nR;
	}
}
/**
 * @brief Generates next plane using a 'hexagonal' type cellular automata rule.
 *
 * Given a bitplane w by h in curBits, generates a new bitplane in nextBits, using a 
 * cellular automaton defined by rule, where rule uses the current pixel and it's
 * four neighbors in rectangular positions above, below, left, right.
 *
 * inrule defines a totalistic cellular automaton using the convention of NKS chapter 5,
 * where cells have 4 neighbors in 6 neighbor positions on a hexagonal grid.
 */
void nextGenHex(BitSequence *curBits, 
				BitSequence *nextBits, BitSequence *temp,
				int w, int h,
				int inrule)
{
	unsigned char *src, *dst, *pTL, *pBL, *pTR, *pBR, *pL, *pR;
	unsigned long *plTL, *plBL, *plTR, *plBR, *plL, *plR;
	uint64_t *nTL, *nBL, *nTR, *nBR, *nL, *nR;
	uint64_t *lD, *lS;
	int ll;
	int r;
	int width = w;
	int stride = w/8;
	int plSz = stride*h;
	int nqw = (h*stride)/8;
	int rule = inrule;

	nqw = (int) ceil((h*stride)/8.0);//hack

	src = curBits;
	dst = nextBits;

	nL = pL =  plL = pL = temp;
	nR = pR =  plR = pR = temp + plSz;
	nTL =pTL = plTL =pTL = temp + 2*plSz;
	nTR =pTR = plTR =pTR = temp + 3*plSz;
	nBL =pBL = plBL =pBL = temp + 4*plSz;
	nBR =pBR = plBR =pBR = temp + 5*plSz;

	for(r=0; r<h;r++){
		int prevrow = -stride;
		int nextrow = stride;
		if(r == 0){
#ifdef TOROID_TOPOLOGY
			prevrow = h*(stride - 1);
#else
			prevrow = stride;
#endif
		}
		if(r == h-1){
#ifdef TOROID_TOPOLOGY
			nextrow = -h*(stride - 1);
#else
			nextrow = -stride;
#endif
		}

		memcpy(pTL,src + prevrow,stride);
		memcpy(pBL,src + nextrow,stride);
		if(r & 1){
			ShiftLeft(pTR,src + prevrow,stride);
			ShiftLeft(pBR,src + nextrow,stride);
		}else {
			ShiftRight(pTR,src + prevrow,stride);
			ShiftRight(pBR,src + nextrow,stride);
		}

		ShiftRight(pL,src,stride);
		ShiftLeft(pR,src,stride);
		pTR += stride;
		pTL += stride;
		pBR += stride;
		pBL += stride;
		pL += stride;
		pR += stride;
		src += stride;
		dst += stride;
	}
	src = curBits;
	dst = nextBits;

	lS = (uint64_t *)src;
	lD = (uint64_t *)dst;

	for(ll = 0; ll < nqw; ll++)
	{
		uint64_t mask = 0x1111111111111111;
		uint64_t bm = 0x1;
		uint64_t nBits;
		int i,j;

		*lD = 0;
		
		for(j=0;j<4;j++)
		{
			char *dc = (char *) lD;

			nBits = 0;
			nBits += (*nTL  >> j) & mask;
			nBits += (*nBL  >> j) & mask;
			nBits += (*nTR  >> j) & mask;
			nBits += (*nBR  >> j) & mask;
			nBits += (*nL  >> j) & mask;
			nBits += (*nR  >> j) & mask;
			nBits <<= 1;
			nBits += (*lS  >> j) & mask;

			
			for(i=0;i<8;i++)
			{
				char *nbc = (char *) &nBits;
				char *dc = (char *) lD;
				unsigned char btH = (nbc[i] >> 4) & 0xf;
				unsigned char btL = nbc[i] & 0xf;
				unsigned char obitH = ((rule >> btH) & 1);
				unsigned char obitL = ((rule >> btL) & 1);
				dc[i] |= (obitH << (j+4)) | (obitL << j);	
			}
		}
		
		++lS;
		++lD;
		++nTL;
		++nBL;
		++nTR;
		++nBR;
		++nL;
		++nR;
	}
}

/**
 * @brief Version of nextGenHex optimized for very large data.
 *
 * The cellular automata rule interpretation is optimized using a cached table.
 * This is unsuitable for short data as the table generation takes considerable cpu time.
 */
void nextGenHexOptBig(BitSequence *curBits, 
				BitSequence *nextBits, BitSequence *temp,
				int w, int h,
				int inrule, void **tableCache)
{
	unsigned char *src, *dst, *pTL, *pBL, *pTR, *pBR, *pL, *pR;
	unsigned long *plTL, *plBL, *plTR, *plBR, *plL, *plR;
	uint64_t *nTL, *nBL, *nTR, *nBR, *nL, *nR;
	uint64_t *lD, *lS;
	int ll,k;
	int r;
	int width = w;
	int stride = w/8;
	int plSz = stride*h;
	int nqw = (int) ceil((h*stride)/8.0);

	int rule = inrule;

	unsigned short *ruletab;

	if(*tableCache == NULL){
		*tableCache = calloc(65536,sizeof(short));

		ruletab = (short *) *tableCache;
		for(k=0;k<65536;k++){
			unsigned char btH = (k >> 4) & 0xf;
			unsigned char btL = k & 0xf;
			unsigned char obitH = ((rule >> btH) & 1);
			unsigned char obitL = ((rule >> btL) & 1);
			ruletab[k] = (obitH << 4) | obitL;
			btH = (k >> 12) & 0xf;
			btL = (k >> 8) & 0xf;
			obitH = ((rule >> btH) & 1);
			obitL = ((rule >> btL) & 1);
			ruletab[k] |= ((obitH << 4) | obitL) << 8;
		}
	}
	ruletab = (short *) *tableCache;

	src = curBits;
	dst = nextBits;

	nL = pL =  plL = pL = temp;
	nR = pR =  plR = pR = temp + plSz;
	nTL =pTL = plTL =pTL = temp + 2*plSz;
	nTR =pTR = plTR =pTR = temp + 3*plSz;
	nBL =pBL = plBL =pBL = temp + 4*plSz;
	nBR =pBR = plBR =pBR = temp + 5*plSz;

	for(r=0; r<h;r++){
		int prevrow = -stride;
		int nextrow = stride;
		if(r == 0){
#ifdef TOROID_TOPOLOGY
			prevrow = h*(stride - 1);
#else
			prevrow = stride;
#endif
		}
		if(r == h-1){
#ifdef TOROID_TOPOLOGY
			nextrow = -h*(stride - 1);
#else
			nextrow = -stride;
#endif
		}
		memcpy(pTL,src + prevrow,stride);
		memcpy(pBL,src + nextrow,stride);
		if(r & 1){
			ShiftLeft(pTR,src + prevrow,stride);
			ShiftLeft(pBR,src + nextrow,stride);
		}else {
			ShiftRight(pTR,src + prevrow,stride);
			ShiftRight(pBR,src + nextrow,stride);
		}

		ShiftRight(pL,src,stride);
		ShiftLeft(pR,src,stride);
		pTR += stride;
		pTL += stride;
		pBR += stride;
		pBL += stride;
		pL += stride;
		pR += stride;
		src += stride;
		dst += stride;
	}
	src = curBits;
	dst = nextBits;

	lS = (uint64_t *)src;
	lD = (uint64_t *)dst;

	for(ll = 0; ll < nqw; ll++)
	{
		uint64_t mask = 0x1111111111111111;
		uint64_t bm = 0x1;
		uint64_t nBits;
		int i,j;

		*lD = 0;
		
		for(j=0;j<4;j++)
		{
			unsigned short *nbs;
			unsigned short *ds = (unsigned short *) lD;

			nBits = 0;
			nBits += (*nTL  >> j) & mask;
			nBits += (*nBL  >> j) & mask;
			nBits += (*nTR  >> j) & mask;
			nBits += (*nBR  >> j) & mask;
			nBits += (*nL  >> j) & mask;
			nBits += (*nR  >> j) & mask;
			nBits <<= 1;
			nBits += (*lS  >> j) & mask;

			nbs = (unsigned short *) &nBits;
			for(i=0;i<4;i++)
			{
				*ds++ |= ruletab[*nbs++] << j;	
			}
		}
		
		++lS;
		++lD;
		++nTL;
		++nBL;
		++nTR;
		++nBR;
		++nL;
		++nR;
	}

	return;
}

/**
 * @brief Generates next plane using an eight neighbor type cellular automata rule.
 *
 * Given a bitplane w by h in curBits, generates a new bitplane in nextBits, using a 
 * cellular automaton defined by rule, where rule uses the current pixel and it's
 * four neighbors in rectangular positions above, below, left, right.
 *
 * inrule defines a totalistic cellular automaton using the convention of NKS chapter 5,
 * where cells have neighbors in 8 adjacent positions, e.g. 4 rectangular plus 4 diagonal positions.
 */
void nextGenAll(BitSequence *curBits, 
				BitSequence *nextBits, BitSequence *temp,
				int w, int h,
				int inrule)
{
	unsigned char *src, *dst, *pT, *pB, *pL, *pR, *pDT, *pDB, *pDL, *pDR;
	unsigned long *plT, *plB, *plL, *plR, *plDT, *plDB, *plDL, *plDR;
	uint64_t *nT, *nB, *nL, *nR,*nDT, *nDB, *nDL, *nDR;
	uint64_t *lD, *lS;
	int ll;
	int r;
	int width = w;
	int stride = w/8;
	int plSz = stride*h;
	int nqw = (h*stride)/8;
	int rule = inrule;

	src = curBits;
	dst = nextBits;

	pT = temp;
	pB = temp + plSz;
	pL = temp + 2*plSz;
	pR = temp + 3*plSz;
	pDT = temp + 4*plSz;
	pDB = temp + 5*plSz;
	pDL = temp + 6*plSz;
	pDR = temp + 7*plSz;

	nT   = plT =  pT = temp;
	nB	 = plB =  pB = temp + plSz;
	nL	 = plL =  pL = temp + 2*plSz;
	nR	 = plR =  pR = temp + 3*plSz;
	nDT	 = plDT =  pDT = temp + 4*plSz;
	nDB	 = plDB =  pDB = temp + 5*plSz;
	nDL	 = plDL =  pDL = temp + 6*plSz;
	nDR	 = plDR =  pDR = temp + 7*plSz;

	for(r=0; r<h;r++){
		if(r == 0){
#ifdef TOROID_TOPOLOGY
			memcpy(pT,src+(h-1)*stride,stride);
			rolRight(pDT,src+(h-1)*stride,stride);
			rolLeft(pDR,src+(h-1)*stride,stride);
#else
			memcpy(pT,src+stride,stride);
			ShiftRight(pDT,src+stride,stride);
			ShiftLeft(pDR,src+stride,stride);
#endif
		} else {
			memcpy(pT,src - stride,stride);
			ShiftRight(pDT,src - stride,stride);
			ShiftLeft(pDR,src - stride,stride);
		}
		if(r == h-1){
#ifdef TOROID_TOPOLOGY
			memcpy(pB,src - (h-1)*stride,stride);
			rolRight(pDL,src - (h-1)*stride,stride);
			rolLeft(pDB,src - (h-1)*stride,stride);
#else
			memcpy(pB,src - stride,stride);
			ShiftRight(pDL,src - stride,stride);
			ShiftLeft(pDB,src - stride,stride);
#endif
		} else {
			memcpy(pB,src + stride,stride);
			ShiftRight(pDL,src + stride,stride);
			ShiftLeft(pDB,src + stride,stride);
		}
		ShiftRight(pL,src,stride);
		ShiftLeft(pR,src,stride);

		pT  += stride;
		pB  += stride;
		pL  += stride;
		pR  += stride;
		pDT += stride;
		pDB += stride;
		pDL += stride;
		pDR += stride;

		src += stride;
		dst += stride;
	}

	src = curBits;
	dst = nextBits;

	pT = temp;
	pB = temp + plSz;
	pL = temp + 2*plSz;
	pR = temp + 3*plSz;
	pDT = temp + 4*plSz;
	pDB = temp + 5*plSz;
	pDL = temp + 6*plSz;
	pDR = temp + 7*plSz;

	lS = (uint64_t *)src;
	lD = (uint64_t *)dst;

	for(ll = 0; ll < nqw; ll++)
	{
		uint64_t mask = 0x1111111111111111;
		uint64_t bm = 0x1;
		uint64_t nBits;
		int j,k;

		*lD = 0;
		for(j=0;j<4;j++)
		{
				unsigned char *nbc = (unsigned char *) &nBits;
				unsigned char *nbs = (unsigned char *) lS;
				unsigned char *bd = (unsigned char *) lD;
				nBits = 0;
				nBits += (*nT  >> j) & mask;
				nBits += (*nB  >> j) & mask;
				nBits += (*nL  >> j) & mask;
				nBits += (*nR  >> j) & mask;
				nBits += (*nDT  >> j) & mask;
				nBits += (*nDB  >> j) & mask;
				nBits += (*nDL  >> j) & mask;
				nBits += (*nDR  >> j) & mask;

				for(k=0;k<8;k++)
				{
					unsigned char nbb;
					int obit;
					nbb = (nbc[k] >> 4) & 0xf;
					nbb <<= 1;
					nbb += (nbs[k] >> (4 + j)) & 1;

					obit = ((rule >> nbb) & 1);
					bd[k] |= (obit << (4 + j));

					nbb = nbc[k] & 0xf;
					nbb <<= 1;
					nbb += (nbs[k]  >> j) & 1;

					obit = ((rule >> nbb) & 1);
					bd[k] |= (obit << j);
				}
		}
		++lS;
		++lD;
		++nT;   
		++nB;	 
		++nL;
		++nR;	 
		++nDT;	 
		++nDB;	 
		++nDL;	 
		++nDR;
	}
}

/**
 * @brief Generates next bit plane using given cellular automata rule.
 */
void nextGen(BitSequence *curBits, 
		BitSequence *nextBits, 
		BitSequence *temp, 
		int w, int h, int rule, int flags, void **tableCache)
{
	if((rule & ALL_NEIGHBORS) == ALL_NEIGHBORS)
	{ 
		nextGenAll(curBits,nextBits,temp,w,h,rule);
	} 
	else if(rule & RECT_NEIGHBORS)
	{
		nextGenRect(curBits,nextBits,temp,w,h,rule);
	}
	else if(rule & DIAG_NEIGHBORS)
	{
		nextGenDiag(curBits,nextBits,temp,w,h,rule);
	}
	else if(rule & HEX_NEIGHBORS)
	{
		if(flags & LARGEDATA){
			nextGenHexOptBig(curBits,nextBits,temp,w,h,rule,tableCache);
		} else {
			nextGenHex(curBits,nextBits,temp,w,h,rule);
		}
	}
	return;
}
