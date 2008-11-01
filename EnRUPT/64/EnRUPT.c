/*\
\ / Unrolled EnRUPT hash implementing irRUPT32-224, irRUPT32-256, irRUPT64-384 and irRUPT64-512 stream hashing modes of operation for P=2 and s=4
/ \ Designed and implemented by Sean O'Neil
\ / NIST SHA-3 submission by VEST Corporation
/ \ Released to the public domain by the author on November 1, 2008.
\*/

#include "SHA3api_ref.h"
#include "stdio.h"

#if defined(ENRUPT64_TYPE)&&(ENRUPT64_TYPE==1)		/* EnRUPT64 with SSE via compiler intrinsics */

#define uw64				__m128i
#define x64					((uw64 *) state->x)
#define p64					((uio64 *) state->p)

#define ir2_64(R,H)\
(\
	f=_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_slli_epi64(_mm_shuffle_epi32(x64[(R)%H/2+2],0x4E),1),d),r),x64[(R+4)%H/2+2]),\
	r=_mm_add_epi64(r,_sse_2),\
	f=_mm_xor_si128(_mm_srli_epi64(f,16),_mm_slli_epi64(f,48)),\
	f=_mm_add_epi64(_mm_slli_epi64(f,3),f),\
	x64[(R+2)%H/2+2]=_mm_xor_si128(f,x64[(R+2)%H/2+2]),\
	d=_mm_xor_si128(_mm_xor_si128(d,x64[(R)%H/2+2]),f)\
)
#if defined(__amd64__)||defined(__x86_64__)||defined(_M_IA64)||defined(_M_X64)	/* x64 SSE intrinsics are slightly different */
	#define uio64				u64
	#define ir8_64(R,W,H,p,n)	(ir08(R,W,H),d=_mm_xor_si128(d,_mm_set1_epi64x(bswap64((p)[n]))))
	#define sw64(hw,n)			((hw)[n]=bswap64(_mm_cvtsi128_si64x(_mm_shuffle_epi32(d,0xEE))))
	#define irufinish64()		x64[0]=d,x64[1]=r
	#define irfdefine64()
	#define irffinish64()
#elif defined(i386)||defined(__i386__)||defined(_M_IX86)
	#define uio64				__m64
	#define bswap64mmi(p)		(_mm_shuffle_pi16(_mm_xor_si64(_mm_slli_pi16(p,8),_mm_srli_pi16(p,8)),0x1B))
	#define ir8_64(R,W,H,p,n)	(ir08(R,W,H),d=_mm_xor_si128(d,_mm_shuffle_epi32(_mm_movpi64_epi64(bswap64mmi((p)[n])),0x4E)))
	#define sw64(hw,n)			(o=_mm_movepi64_pi64(_mm_shuffle_epi32(d,0xEE)),(hw)[n]=bswap64mmi(o))
	#define irfdefine64()		register uio64 o
	#define irufinish64()		x64[0]=d,x64[1]=r,_mm_empty()
	#define irffinish64()		_mm_empty()
#else
	#error Unknown processor type. Is it IA32 or IA64?
#endif
#define irudefine64()		register uw64 d=x64[0],r=x64[1],f

#ifdef __GNUC__
	static __m128i			_sse_2 = {2,2};
#else
	static __m128i			_sse_2 = {2,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0};
#endif

#elif defined(ENRUPT64_TYPE)&&(ENRUPT64_TYPE==2)	/* EnRUPT64 with u32 */

#define uw64				u32
#define uio64				u32
#define x64					((uw64 *) state->x)
#define p64					((uio64 *) state->p)

#if defined(ENRUPT_1234_BYTE_ORDER)
	#define lw64(p,n)		(x64[3]^=bswap32((p)[(n)*2]),x64[2]^=bswap32((p)[(n)*2+1]))
	#define sw64(hw,n)		((hw)[(n)*2]=bswap32(x64[3]),(hw)[(n)*2+1]=bswap32(x64[2]))
#elif defined(ENRUPT_4321_BYTE_ORDER)
	#define lw64(p,n)		(x64[2]^=(p)[(n)*2],x64[3]^=(p)[(n)*2+1])
	#define sw64(hw,n)		((hw)[(n)*2]=x64[2],(hw)[(n)*2+1]=x64[3])
#else
	#error Unknown endianness! Please define.
#endif
#define ir1_64(R,H)\
(\
	f1=((x64[(R^1)%H*2+9]<<1)+(x64[(R^1)%H*2+8]>>31))^x64[(R+4)%H*2+9]^x64[((R)&1)*2+1]^x64[5],\
	f0= (x64[(R^1)%H*2+8]<<1)^x64[(R+4)%H*2+8]^x64[((R)&1)*2]^x64[4],\
	t=(f0>>16)+(f1<<16),f1=(f1>>16)+(f0<<16),f0=t*9,f1+=(f1<<3)+(t>>29)+(f0<t),\
	x64[5]+=!(++x64[4]),\
	x64[(R+2)%H*2+8]^=f0,x64[(R+2)%H*2+9]^=f1,\
	x64[((R)&1)*2]^=x64[(R)%H*2+8],x64[((R)&1)*2+1]^=x64[(R)%H*2+9],\
	x64[((R)&1)*2]^=f0,x64[((R)&1)*2+1]^=f1\
)
#define ir8_64(R,W,H,p,n)	(ir08(R,W,H),lw64(p,n))
#define ir2_64(R,H)			(ir1_64(R,H),ir1_64(R+1,H))
#define irudefine64()		register uw64 f0, f1, t
#define irfdefine64()
#define irufinish64()
#define irffinish64()

#else						/* EnRUPT64 with u64, a generic implementation */

#define uw64				u64
#define uio64				u64
#define x64					((uw64 *) state->x)
#define p64					((uio64 *) state->p)

#if defined(ENRUPT_1234_BYTE_ORDER)
	#define lw64(p,n)		(x64[1]^=bswap64((p)[n]))
	#define sw64(hw,n)		((hw)[n]=bswap64(x64[1]))
#elif defined(ENRUPT_4321_BYTE_ORDER)
	#define lw64(p,n)		(x64[1]^=(p)[n])
	#define sw64(hw,n)		((hw)[n]=x64[1])
#else
	#error Unknown endianness! Please define.
#endif

#define ir1_64(R,H)\
(\
	f=shl64(x64[(R^1)%H+4],1),\
	f^=x64[(R+4)%H+4],\
	f^=x64[2],\
	f^=x64[(R)&1],\
	f=rotr64(f,16),\
	x64[2]++,\
	f+=shl64(f,3),\
	x64[(R+2)%H+4]^=f,\
	x64[(R)&1]^=x64[(R)%H+4],\
	x64[(R)&1]^=f\
)
#define ir8_64(R,W,H,p,n)	(ir08(R,W,H),lw64(p,n))
#define ir2_64(R,H)			(ir1_64(R,H),ir1_64(R+1,H))
#define irudefine64()		register uw64 f
#define irfdefine64()
#define irufinish64()
#define irffinish64()

#endif

#if defined(ENRUPT32_TYPE)&&(ENRUPT32_TYPE==1)		/* EnRUPT32 with MMX via compiler intrinsics (on x64: GCC only, not yet supported by MSVC or Intel compiler) */

#define uw32				__m64
#define uio32				u32
#define x32					((uw32 *) state->x)
#define p32					((uio32 *) state->p)

#define ir2_32(R,H)\
(\
	f=_mm_xor_si64(_mm_xor_si64(_mm_xor_si64(_mm_slli_pi32(_mm_shuffle_pi16(x32[(R)%H/2+2],0x4E),1),d),r),x32[(R+4)%H/2+2]),\
	r=_mm_add_pi32(r,_mmx_2),\
	f=_mm_xor_si64(_mm_srli_pi32(f,8),_mm_slli_pi32(f,24)),\
	f=_mm_add_pi32(_mm_slli_pi32(f,3),f),\
	x32[(R+2)%H/2+2]=_mm_xor_si64(f,x32[(R+2)%H/2+2]),\
	d=_mm_xor_si64(_mm_xor_si64(d,x32[(R)%H/2+2]),f)\
)
#define ir8_32(R,W,H,p,n)	(ir08(R,W,H),d=_mm_xor_si64(d,_mm_shuffle_pi16(_mm_cvtsi32_si64(bswap32((p)[n])),0x4E)))
#define sw32(hw,n)			((hw)[n]=bswap32(_mm_cvtsi64_si32(_mm_shuffle_pi16(d,0xEE))))
#define irudefine32()		register uw32 d=x32[0],r=x32[1],f
#define irufinish32()		x32[0]=d,x32[1]=r,_mm_empty()
#define irfdefine32()
#define irffinish32()		_mm_empty()

#if !defined(__GNUC__)||!defined(__STDC__)||defined(__APPLE_CC__)&&(__APPLE_CC__>1)
	static __m64			_mmx_2 = {0x200000002ULL};	/* MSVC, Intel Compiler and Apple GCC */
#else
	static __m64			_mmx_2 = {2,2};		/* Most versions of GCC require two 32-bit constants here. Watch out! */
#endif

#elif defined(ENRUPT32_TYPE)&&(ENRUPT32_TYPE==2)	/* EnRUPT32 with (mostly) u64 */

#define uw32				u64
#define uio32				u32
#define x32					((uw32 *) state->x)
#define p32					((uio32 *) state->p)

#define ir8_32(R,W,H,p,n)	(ir08(R,W,H),d.d[1]^=bswap32((p)[n]))
#define sw32(hw,n)			((hw)[n]=bswap32(d.d[1]))
#define ir2_32(R,H)\
(\
	f.q=(rotr64(x32[(R)%H/2+2],31)&0xFFFFFFFEFFFFFFFEULL)^d.q^r.q^x32[(R+4)%H/2+2],\
	r.d[0]+=2,r.d[1]+=2,\
	f.d[0]=rotr32(f.d[0],8),f.d[1]=rotr32(f.d[1],8),\
	f.d[0]+=f.d[0]<<3,f.d[1]+=f.d[1]<<3,\
	x32[(R+2)%H/2+2]^=f.q,\
	d.q^=f.q^x32[(R)%H/2+2]\
)
#define irudefine32()		register ir_octet d,r,f;d.q=x32[0],r.q=x32[1]
#define irfdefine32()
#define irufinish32()		x32[0]=d.q,x32[1]=r.q
#define irffinish32()

#else						/* EnRUPT32 with u32, a generic implementation */

#define uw32				u32
#define uio32				u32
#define x32					((uw32 *) state->x)
#define p32					((uio32 *) state->p)

#if defined(ENRUPT_1234_BYTE_ORDER)
	#define lw32(p,n)		(x32[1]^=bswap32((p)[n]))
	#define sw32(hw,n)		((hw)[n]=bswap32(x32[1]))
#elif defined(ENRUPT_4321_BYTE_ORDER)
	#define lw32(p,n)		(x32[1]^=(p)[n])
	#define sw32(hw,n)		((hw)[n]=x32[1])
#else
	#error Unknown endianness! Please define.
#endif
#define ir2_32(R,H)\
(\
	f0=x32[(R+1)%H+4]<<1,	f1=x32[(R)%H+4]<<1,\
	f0^=x32[(R+4)%H+4],		f1^=x32[(R+5)%H+4],\
	f0^=x32[2],				f1^=x32[3],\
	f0^=x32[0],				f1^=x32[1],\
	f0=rotr32(f0,8),		f1=rotr32(f1,8),\
	x32[2]+=2,				x32[3]+=2,\
	f0+=f0<<3,				f1+=f1<<3,\
	x32[(R+2)%H+4]^=f0,		x32[(R+3)%H+4]^=f1,\
	x32[0]^=x32[(R)%H+4],	x32[1]^=x32[(R+1)%H+4],\
	x32[0]^=f0,				x32[1]^=f1\
)
#define ir8_32(R,W,H,p,n)	(ir08(R,W,H),lw32(p,n))
#define irudefine32()		register uw32 f0, f1
#define irfdefine32()
#define irufinish32()
#define irffinish32()

#endif

#define ir08(R,W,H)			(ir2_##W(R,H),ir2_##W(R+2,H),ir2_##W(R+4,H),ir2_##W(R+6,H))
#define ir8(R,W,H,p,n)		(ir8_##W(R,W,H,p,n))

#define EnRUPTxH_8(p,W)		(ir8(0,W, 8,p,0),ir8(8,W, 8,p,1),ir8(16,W, 8,p,2),ir8(24,W, 8,p,3))
#define EnRUPTxH_10(p,W)	(ir8(0,W,10,p,0),ir8(8,W,10,p,1),ir8(16,W,10,p,2),ir8(24,W,10,p,3),ir8(32,W,10,p,4))
#define EnRUPTxH_12(p,W)	(ir8(0,W,12,p,0),ir8(8,W,12,p,1),ir8(16,W,12,p,2),ir8(24,W,12,p,3),ir8(32,W,12,p,4),ir8(40,W,12,p,5))
#define EnRUPTxH_14(p,W)	(ir8(0,W,14,p,0),ir8(8,W,14,p,1),ir8(16,W,14,p,2),ir8(24,W,14,p,3),ir8(32,W,14,p,4),ir8(40,W,14,p,5),ir8(48,W,14,p,6))
#define EnRUPTxH_16(p,W)	(ir8(0,W,16,p,0),ir8(8,W,16,p,1),ir8(16,W,16,p,2),ir8(24,W,16,p,3),ir8(32,W,16,p,4),ir8(40,W,16,p,5),ir8(48,W,16,p,6),ir8(56,W,16,p,7))
#define EnRUPT0x1_8(W)		ir08(0,W,8)
#define EnRUPT0x1_10(W)		((iri==0)?(ir08(0,W,10),iri=8):(iri==2)?(ir08(2,W,10),iri= 0):(iri==4)?(ir08(4,W,10),iri= 2):(iri==6)?(ir08(6,W,10),iri=4):(iri==8)?(ir08(8,W,10),iri=6))
#define EnRUPT0x1_12(W)		((iri==0)?(ir08(0,W,12),iri=8):(iri==2)?(ir08(2,W,12),iri=10):(iri==4)?(ir08(4,W,12),iri= 0):(iri==6)?(ir08(6,W,12),iri=2):(iri==8)?(ir08(8,W,12),iri=4):(ir08(10,W,12),iri=6))
#define EnRUPT0x1_14(W)		((iri==0)?(ir08(0,W,14),iri=8):(iri==2)?(ir08(2,W,14),iri=10):(iri==4)?(ir08(4,W,14),iri=12):(iri==6)?(ir08(6,W,14),iri=0):(iri==8)?(ir08(8,W,14),iri=2):(iri==10)?(ir08(10,W,14),iri=4):(ir08(12,W,14),iri=6))
#define EnRUPT0x1_16(W)		((iri==0)?(ir08(0,W,16),iri=8):(ir08(8,W,16),iri=0))
#define EnRUPT0xH_8(h,W)	(ir8(0,W, 8,h,0),ir08(8,W, 8),ir08(16,W, 8),ir08(24,W, 8))
#define EnRUPT0xH_10(h,W)	(ir8(0,W,10,h,0),ir08(8,W,10),ir08(16,W,10),ir08(24,W,10),ir08(32,W,10))
#define EnRUPT0xH_12(h,W)	(ir8(0,W,12,h,0),ir08(8,W,12),ir08(16,W,12),ir08(24,W,12),ir08(32,W,12),ir08(40,W,12))
#define EnRUPT0xH_14(h,W)	(ir8(0,W,14,h,0),ir08(8,W,14),ir08(16,W,14),ir08(24,W,14),ir08(32,W,14),ir08(40,W,14),ir08(48,W,14))
#define EnRUPT0xH_16(h,W)	(ir8(0,W,16,h,0),ir08(8,W,16),ir08(16,W,16),ir08(24,W,16),ir08(32,W,16),ir08(40,W,16),ir08(48,W,16),ir08(56,W,16))

#define define_EnRUPT_Update(W,h,H)\
HashReturn EnRUPTu##W##_##h (hashState *state, const BitSequence *data, DataLength databitlen)\
{\
	size_t				i = H*W/2-state->n;\
	irudefine##W();\
	\
	if (state->n&7)\
	{\
		irufinish##W();\
		return FAIL;\
	}\
	if (databitlen < i)\
	{\
		memcpy (state->p+(state->n>>3),data,(databitlen+7)>>3);\
		state->n += (int)databitlen;\
		irufinish##W();\
		return SUCCESS;\
	}\
	if (state->n)\
	{\
		memcpy (state->p+(state->n>>3),data,i>>3);\
		EnRUPTxH_##H (p##W, W);\
		databitlen -= i;\
		state->n = 0;\
	}\
	else i = 0;\
	for (; databitlen >= H*W/2; databitlen -= H*W/2, i += H*W/2)\
	{\
		EnRUPTxH_##H ((uio##W *)(data+(i>>3)), W);\
	}\
	irufinish##W();\
	if ((int)databitlen)\
	{\
		memcpy (state->p, data+(i>>3), (databitlen+7)>>3);\
		state->n = (int)databitlen;\
	}\
	return SUCCESS;\
}

#define define_EnRUPT_Final(W,h,H)\
HashReturn EnRUPTf##W##_##h (hashState *state, BitSequence *hashval)\
{\
	register int		i = state->n>>3, j = (state->n&7)^7, iri = 0;\
	\
	irudefine##W();\
	irfdefine##W();\
	\
	if (state->n < 0)\
	{\
		irffinish##W();\
		return FAIL;\
	}\
	state->p[i] &= -1 << j;\
	state->p[i] |=  1 << j;\
	memset (state->p+i+1,0,(H+4)*W/16-i-1);\
	state->p[(i+W/8)|(W/8-1)] = h;\
	state->p[((i+W/8)|(W/8-1))-1] = h>>8;\
	EnRUPTxH_##H (p##W, W);\
	EnRUPT0xH_##H ((uio##W *)(state->p+H*W/16),W);\
	for (i = state->n/W+2; i; i--) { EnRUPT0x1_##H (W); }\
	for (i = 0; i < h/W; i++) { EnRUPT0x1_##H (W); sw##W ((uio##W *)hashval,i); }\
	if (h%W) { u8 lasth[W/8]; EnRUPT0x1_##H (W); sw##W ((uio##W *)lasth,0); memcpy (hashval+(h-h%W)/8, lasth, (h%W+7)/8); }\
	irffinish##W();\
	state->n = -1;\
	return SUCCESS;\
}

/*	Include only the sizes you need or it may take too long to compile. */

/*	define_EnRUPT_Update(32,  64, 4)	define_EnRUPT_Final(32,  64, 4)	*/
/*	define_EnRUPT_Update(32,  96, 6)	define_EnRUPT_Final(32,  96, 6)	*/
/*	define_EnRUPT_Update(32, 128, 8)	define_EnRUPT_Final(32, 128, 8)	*/
/*	define_EnRUPT_Update(32, 160,10)	define_EnRUPT_Final(32, 160,10)	*/
/*	define_EnRUPT_Update(32, 192,12)	define_EnRUPT_Final(32, 192,12)	*/
/*	define_EnRUPT_Update(32, 224,14)	define_EnRUPT_Final(32, 224,14)	*/
/*	define_EnRUPT_Update(32, 256,16)	define_EnRUPT_Final(32, 256,16)	*/
/*	define_EnRUPT_Update(32, 288,18)	define_EnRUPT_Final(32, 288,18)	*/
/*	define_EnRUPT_Update(32, 320,20)	define_EnRUPT_Final(32, 320,20)	*/
/*	define_EnRUPT_Update(32, 352,22)	define_EnRUPT_Final(32, 352,22)	*/
/*	define_EnRUPT_Update(32, 384,24)	define_EnRUPT_Final(32, 384,24)	*/
/*	define_EnRUPT_Update(32, 416,26)	define_EnRUPT_Final(32, 416,26)	*/
/*	define_EnRUPT_Update(32, 448,28)	define_EnRUPT_Final(32, 448,28)	*/
/*	define_EnRUPT_Update(32, 480,30)	define_EnRUPT_Final(32, 480,30)	*/
/*	define_EnRUPT_Update(32, 512,32)	define_EnRUPT_Final(32, 512,32)	*/
/*	define_EnRUPT_Update(32, 544,34)	define_EnRUPT_Final(32, 544,34)	*/
/*	define_EnRUPT_Update(32, 576,36)	define_EnRUPT_Final(32, 576,36)	*/
/*	define_EnRUPT_Update(32, 608,38)	define_EnRUPT_Final(32, 608,38)	*/
/*	define_EnRUPT_Update(32, 640,40)	define_EnRUPT_Final(32, 640,40)	*/
/*	define_EnRUPT_Update(32, 672,42)	define_EnRUPT_Final(32, 672,42)	*/
/*	define_EnRUPT_Update(32, 704,44)	define_EnRUPT_Final(32, 704,44)	*/
/*	define_EnRUPT_Update(32, 736,46)	define_EnRUPT_Final(32, 736,46)	*/
/*	define_EnRUPT_Update(32, 768,48)	define_EnRUPT_Final(32, 768,48)	*/

/*	define_EnRUPT_Update(64, 128, 4)	define_EnRUPT_Final(64, 128, 4)	*/
/*	define_EnRUPT_Update(64, 160, 6)	define_EnRUPT_Final(64, 160, 6)	*/
/*	define_EnRUPT_Update(64, 192, 6)	define_EnRUPT_Final(64, 192, 6)	*/
/*	define_EnRUPT_Update(64, 224, 8)*/	define_EnRUPT_Final(64, 224, 8)
	define_EnRUPT_Update(64, 256, 8)	define_EnRUPT_Final(64, 256, 8)
/*	define_EnRUPT_Update(64, 320,10)	define_EnRUPT_Final(64, 320,10)	*/
	define_EnRUPT_Update(64, 384,12)	define_EnRUPT_Final(64, 384,12)
/*	define_EnRUPT_Update(64, 448,14)	define_EnRUPT_Final(64, 448,14)	*/
	define_EnRUPT_Update(64, 512,16)	define_EnRUPT_Final(64, 512,16)
/*	define_EnRUPT_Update(64, 576,18)	define_EnRUPT_Final(64, 576,18)	*/
/*	define_EnRUPT_Update(64, 640,20)	define_EnRUPT_Final(64, 640,20)	*/
/*	define_EnRUPT_Update(64, 704,22)	define_EnRUPT_Final(64, 704,22)	*/
/*	define_EnRUPT_Update(64, 768,24)	define_EnRUPT_Final(64, 768,24)	*/
/*	define_EnRUPT_Update(64, 832,26)	define_EnRUPT_Final(64, 832,26)	*/
/*	define_EnRUPT_Update(64, 896,28)	define_EnRUPT_Final(64, 896,28)	*/
/*	define_EnRUPT_Update(64, 960,30)	define_EnRUPT_Final(64, 960,30)	*/
/*	define_EnRUPT_Update(64,1024,32)	define_EnRUPT_Final(64,1024,32)	*/
/*	define_EnRUPT_Update(64,1088,34)	define_EnRUPT_Final(64,1088,34)	*/
/*	define_EnRUPT_Update(64,1152,36)	define_EnRUPT_Final(64,1152,36)	*/
/*	define_EnRUPT_Update(64,1216,38)	define_EnRUPT_Final(64,1216,38)	*/
/*	define_EnRUPT_Update(64,1280,40)	define_EnRUPT_Final(64,1280,40)	*/
/*	define_EnRUPT_Update(64,1344,42)	define_EnRUPT_Final(64,1344,42)	*/
/*	define_EnRUPT_Update(64,1408,44)	define_EnRUPT_Final(64,1408,44)	*/
/*	define_EnRUPT_Update(64,1472,46)	define_EnRUPT_Final(64,1472,46)	*/
/*	define_EnRUPT_Update(64,1536,48)	define_EnRUPT_Final(64,1536,48)	*/

#define EnRUPT_Init(s)\
{\
	memset (s, 0, sizeof(*s));\
	(s)->hashbitlen = hashbitlen;\
	switch (hashbitlen)\
	{\
	case 224: (s)->u=(iru*)&EnRUPTu64_256,(s)->f=(irf*)&EnRUPTf64_224;((u32*)(s)->x)[6]++; break;\
	case 256: (s)->u=(iru*)&EnRUPTu64_256,(s)->f=(irf*)&EnRUPTf64_256;((u32*)(s)->x)[6]++; break;\
	case 384: (s)->u=(iru*)&EnRUPTu64_384,(s)->f=(irf*)&EnRUPTf64_384;((u32*)(s)->x)[6]++; break;\
	case 512: (s)->u=(iru*)&EnRUPTu64_512,(s)->f=(irf*)&EnRUPTf64_512;((u32*)(s)->x)[6]++; break;\
	default: return BAD_HASHBITLEN;\
	}\
}

HashReturn Init (hashState *state, int hashbitlen) { EnRUPT_Init(state) return SUCCESS; }
HashReturn Update (hashState *state, const BitSequence *data, DataLength databitlen) { return state->u (state, data, databitlen); }
HashReturn Final (hashState *state, BitSequence *hashval) { return state->f (state, hashval); }
HashReturn Hash (int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval) { hashState state; EnRUPT_Init(&state) state.u (&state, data, databitlen); return state.f (&state, hashval); }
