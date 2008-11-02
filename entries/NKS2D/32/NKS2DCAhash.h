//---------------NKS 2D Cellular Automata Hash-----------------------
// NKS2DCAhash.h
// 
// Defines interface for SHA3.c and internal structures  and functions
// for NKS2DCAhask.c
//
// Copyright © 2007, Geoffrey Park
//-------------------------------------------------------------------

#include "SHA3api_ref.h"

#define ALL_NEIGHBORS  0x300000
#define RECT_NEIGHBORS 0x100000
#define DIAG_NEIGHBORS 0x200000
#define HEX_NEIGHBORS  0x400000
#define LARGEDATA	   0x800000

void nextGen(BitSequence *curBits, BitSequence *nextBits, BitSequence *temp,
			  int w, int h, int rule, int flags, void **tableCache);
