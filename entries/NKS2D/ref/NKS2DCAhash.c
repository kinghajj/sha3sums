/**
 * @file NKS2DCAhash.c
 * @brief NKS 2D Cellular Automata Hash
 * 
 * Implements 2D cellular automata generator for totalistic
 * generation rules as described in: 
 * "A New Kind of Science"
 * by Stephen Wolfram ISBN I-57955-008-8
 * [referred to below as 'NKS'] 
 * Optionally data can be mixed into each generation to influence the
 * generator output.
 * @author Copyright � 2007, 2008,  Geoffrey Park
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "NKS2DCAhash.h"

/**
 * @brief Returns value of a single bit at position x,y in a
 * bit array w bits wide by h rows
 */
int getBit(unsigned char *bits, int w, int h, int x, int y)
{
	unsigned char mask;
	int byte;
	int bit;

#ifdef TOROID_TOPOLOGY
	// Torus
	if(x < 0) x += w;
	if(y < 0) y += h;
	if(x >= w) x -= w;
	if(y >= h) y -= h;
#else
	// Mirror
	if(x < 0) x += 2;
	if(y < 0) y += 2;
	if(x >= w) x -= 2;
	if(y >= h) y -= 2;
#endif

	byte = bits[y*(w/8) + x/8];
	bit = x - 8*(x/8);
	mask = 0x80 >> bit;

	return( (byte & mask) != 0 ? 1 : 0);
}

/**
 * @brief Sets a single bit at position x,y in a bit array w bits wide by h rows.
 */
void setBit(unsigned char *bits, int w, int h, int x, int y)
{
	unsigned char mask;
	unsigned char *byte = &bits[y*(w/8) + x/8];
	int bit = x - 8*(x/8);
	mask = 0x80 >> bit;
	*byte |= mask;
}

/**
 * @brief Clears a single bit at position x,y in a bit array w bits wide by h rows.
 */
void clrBit(unsigned char *bits, int w, int h, int x, int y)
{
	unsigned char mask;
	unsigned char *byte = &bits[y*(w/8) + x/8];
	int bit = x - 8*(x/8);
	mask = 0x80 >> bit;
	*byte &= ~mask;
}

/**
 * @brief Returns count of black pixels adjacent to the pixel at (x,y) in the four rectangular
 * positions e.g. above, below, left, right.
 *
 * bits  - input bitplane, 1 bit per pixel. 1=black, 0=white.
 * w,h   - dimensions of bitplane.
 */
int totalNeighborsRect(unsigned char *bits, int w, int h, int x, int y)
{
	int total= 0;
	if(getBit(bits,w,h,x  ,y-1)) ++total; // Top
	if(getBit(bits,w,h,x  ,y+1)) ++total; // Bottom
	if(getBit(bits,w,h,x-1,y  )) ++total; // Left
	if(getBit(bits,w,h,x+1,y  )) ++total; // Right

	return total;
}


/**
 * @brief Returns count of black pixels adjacent to the pixel at (x,y)  the four diagonal positions
 * e.g. above-left, above-right, below-left, below-right.
 *
 * bits  - input bitplane, 1 bit per pixel. 1=black, 0=white.
 * w,h   - dimensions of bitplane.
 */

int totalNeighborsDiag(unsigned char *bits, int w, int h, int x, int y)
{
	int total= 0;
	if(getBit(bits,w,h,x-1,y-1)) ++total; // Top Left
	if(getBit(bits,w,h,x+1,y-1)) ++total; // Top Right
	if(getBit(bits,w,h,x-1,y+1)) ++total; // Bottom Left
	if(getBit(bits,w,h,x+1,y+1)) ++total; // Bottom Right
	return total;
}

/**
 * @brief Returns count of black pixels adjacent to the pixel at (x,y) in the six hexagonal neighbor
 *
 * bits  - input bitplane, 1 bit per pixel. 1=black, 0=white.
 * w,h   - dimensions of bitplane.
 */

int totalNeighborsHex(unsigned char *bits, int w, int h, int x, int y)
{
	int total= 0;
	if(getBit(bits,w,h,x-1,y  )) ++total;	// Left
	if(getBit(bits,w,h,x+1,y  )) ++total;	// Right
	if(y & 1){
		if(getBit(bits,w,h,x,y-1  )) ++total;//Top
		if(getBit(bits,w,h,x+1,y-1)) ++total;//Top Right
		if(getBit(bits,w,h,x,y+1  )) ++total;//Bottom
		if(getBit(bits,w,h,x+1,y+1)) ++total;//Bottom Right
	} else {
		if(getBit(bits,w,h,x,y-1  )) ++total;//Top
		if(getBit(bits,w,h,x-1,y-1)) ++total;//Top Left
		if(getBit(bits,w,h,x,y+1  )) ++total;//Bottom
		if(getBit(bits,w,h,x-1,y+1)) ++total;//Bottom Left
	}
	return total;
}

/**
 * @brief Returns count of black pixels adjacent to the pixel at (x,y) in all eight adjacent positions.
 *
 * bits  - input bitplane, 1 bit per pixel. 1=black, 0=white.
 * w,h   - dimensions of bitplane.
 */
int totalNeighbors(unsigned char *bits, int w, int h, int x, int y)
{
	int total= 0;
	if(getBit(bits,w,h,x  ,y-1)) ++total;	//T
	if(getBit(bits,w,h,x  ,y+1)) ++total;	//B
	if(getBit(bits,w,h,x-1,y  )) ++total;	//L
	if(getBit(bits,w,h,x+1,y  )) ++total;	//R
	if(getBit(bits,w,h,x-1,y-1)) ++total;	//TL
	if(getBit(bits,w,h,x+1,y+1)) ++total;	//BR
	if(getBit(bits,w,h,x-1,y+1)) ++total;	//BL
	if(getBit(bits,w,h,x+1,y-1)) ++total;	//TR
	return total;
}

/**
 * @brief Given a bitplane w by h in curBits, generates a new bitplane in 
 * nextBits, using a cellular automaton defined by rule.
 *  
 *  Generation rules are defined using the convention of NKS chapter 5 
 *  for totalistic 2D cellular automata:  
 *  
 *  The last binary digit specifies what color the center cell should
 *  be if all its neighbors were white on the previous step, and it
 *  too was white. The second to last digit specifies what happens if 
 *  all the cells are white, but the center cell itself is black.
 *  Each earlier digit then specifies what should happen if
 *  progressively more neighbor cells are black.
 * 
 *  Cells can be counted as 'neighbors' four ways:
 * 
 *  1) 4 rectangular positions e.g. above, below, left, right
 *  2) 4 diagonal positions e.g. above-left, above-right, below-left, below-right
 *  3) 6 hexagonal neighbor positions on hexagonal grid
 *  4) 8 adjacent positions, e.g. 4 rectangular plus 4 diagonal positions
 * 
 *  example:
 * 
 *  using rule = RECT_NEIGHBORS | 451,  a single black cell iterated for 44
 *  generations will result in the 1st pattern in the top row on page 174 of NKS
 *
 */
void nextGen( BitSequence *curBits,			///<[in] current bitplane
					BitSequence *nextBits,	///<[out] next bitplane
					int w,					///<[in] width of bitplane
					int h,					///<[in] height of bitplane
					int rule)				///<[in] generation rule
{
	int x,y;
	if((rule & ALL_NEIGHBORS) == ALL_NEIGHBORS)
	{
		for(y=0;y<h;y++)
		{
			for(x=0;x<w;x++)
			{
				bool ibit = getBit(curBits,w,h,x,y);
				bool obit = false; 
				int k = 2*totalNeighbors(curBits,w,h,x,y);
				if(ibit)
				{
					++k;
				}
				obit = ((rule & (1 << k)) != 0);

				if(obit)
				{
					setBit(nextBits,w,h,x,y);
				}
				else 
				{
					clrBit(nextBits,w,h,x,y);
				}
			}
		}
	} 
	else if(rule & RECT_NEIGHBORS)
	{
		for( y=0;y<h;y++)
		{
			for(x=0;x<w;x++)
			{
				bool ibit = getBit(curBits,w,h,x,y);
				bool obit = false;
				int k = 2*totalNeighborsRect(curBits,w,h,x,y);
				if(ibit)
				{
					++k;
				}
				obit = ((rule & (1 << k)) != 0);

				if(obit)
				{
					setBit(nextBits,w,h,x,y);
				}
				else 
				{
					clrBit(nextBits,w,h,x,y);
				}
			}
		}
	} 
	else if(rule & DIAG_NEIGHBORS)
	{
		for(y=0;y<h;y++)
		{
			for(x=0;x<w;x++)
			{
				bool ibit = getBit(curBits,w,h,x,y);
				bool obit = false;
				int k = 2*totalNeighborsDiag(curBits,w,h,x,y);
				if(ibit)
				{
					++k;
				}
				obit = ((rule & (1 << k)) != 0);

				if(obit)
				{
					setBit(nextBits,w,h,x,y);
				}
				else 
				{
					clrBit(nextBits,w,h,x,y);
				}
			}
		}
	}
	else if(rule & HEX_NEIGHBORS)
	{
		for(y=0;y<h;y++)
		{
			for(x=0;x<w;x++)
			{
				bool ibit = getBit(curBits,w,h,x,y);
				bool obit = false;
				int k = 2*totalNeighborsHex(curBits,w,h,x,y);
				if(ibit)
				{
					++k;
				}
				obit = ((rule & (1 << k)) != 0);

				if(obit)
				{
					setBit(nextBits,w,h,x,y);
				}
				else 
				{
					clrBit(nextBits,w,h,x,y);
				}
			}
		}
	}
	return;
}

