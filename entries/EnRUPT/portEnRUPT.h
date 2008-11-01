/*\
\ / EnRUPT32 and EnRUPT64 in irRUPT stream hashing mode of operation
/ \ Designed and implemented by Sean O'Neil
\ / NIST SHA-3 submission by VEST Corporation
/ \ Released to the public domain by the author on November 1, 2008.
\ /
/ \ #define ENRUPT32_TYPE 0 for a generic u32 implementation
\ / #define ENRUPT32_TYPE 1 for x86 MMX intrinsics [Intel, MSVC and GCC] (only GCC supports MMX intrinsics on x64)
/ \ #define ENRUPT32_TYPE 2 for a (mostly) u64 implementation
\ /
/ \ #define ENRUPT64_TYPE 0 for a generic u64 implementation
\ / #define ENRUPT64_TYPE 1 for x86 SSE intrinsics [Intel, MSVC and GCC]
/ \ #define ENRUPT64_TYPE 2 for a u32-only implementation
\*/

#ifndef _portEnRUPT_h_
#define _portEnRUPT_h_

#include <limits.h>
#include <memory.h>

#if defined(__INTEL_COMPILER)
	#pragma warning (disable:138 167 177 810)
	#include <ia32intrin.h>
	#include <mmintrin.h>
	#include <xmmintrin.h>
	__m128i _mm_set1_epi64x(__int64 i);
	__int64 _mm_cvtsi128_si64x(__m128i a);
	#ifndef u8
		#define u8			unsigned char
	#endif
	#ifndef u16
		#define u16			unsigned short
	#endif
	#ifndef u32
		#define u32			unsigned long
	#endif
	#ifndef u64
		#define u64			unsigned long long
	#endif
	#define rotl32(x,n)		_lrotl(x,n)
	#define rotr32(x,n)		_lrotr(x,n)
	#define rotl64(x,n)		_rotl64(x,n)
	#define rotr64(x,n)		_rotr64(x,n)
	#define bswap32(x)		_bswap(x)
	#define bswap64(x)		_bswap64(x)
	#define shl64(x,n)		((x)<<(n))
	#define shr64(x,n)		((x)>>(n))
	typedef union _ir_octet {u64 q;u32 d[2];} ir_octet;
#elif defined(_MSC_VER)
	#include <stdlib.h>
	#include <intrin.h>
	#pragma intrinsic(_lrotl,_lrotr,__ll_lshift,__ull_rshift,_rotl64,_rotr64,memcpy,memset)
	#ifndef u8
		#define u8			unsigned char
	#endif
	#ifndef u16
		#define u16			unsigned short
	#endif
	#ifndef u32
		#define u32			unsigned long
	#endif
	#ifndef u64
		#define u64			unsigned long long
	#endif
	#define rotl32(x,n)		_lrotl(x,n)
	#define rotr32(x,n)		_lrotr(x,n)
	#define rotl64(x,n)		_rotl64(x,n)
	#define rotr64(x,n)		_rotr64(x,n)
	#define bswap32(x)		_byteswap_ulong(x)
	#define bswap64(x)		_byteswap_uint64(x)
	#if (SIZE_MAX>ULONG_MAX)
		#define shl64(x,n)	((x)<<(n))
		#define shr64(x,n)	((x)>>(n))
	#else
		#define shl64(x,n)	__ll_lshift(x,n)
		#define shr64(x,n)	__ull_rshift(x,n)
	#endif
	typedef union _ir_octet {u64 q;u32 d[2];} ir_octet;
#else
	#include <limits.h>
	#include <stdint.h>
	#include <inttypes.h>
	#include <sys/types.h>
	#include <mmintrin.h>
	#include <xmmintrin.h>
	#ifndef u8
		#define u8			uint8_t
	#endif
	#ifndef u16
		#define u16			uint16_t
	#endif
	#ifndef u32
		#define u32			uint32_t
	#endif
	#ifndef u64
		#define u64			uint64_t
	#endif
	static u32				rotl32 (u32 x, u32 r) { return (x << (r&31)) | (x >> ((0-r)&31)); }
	static u32				rotr32 (u32 x, u32 r) { return (x >> (r&31)) | (x << ((0-r)&31)); }
	static u64				rotl64 (u64 x, u32 r) { return (x << (r&63)) | (x >> ((0-r)&63)); }
	static u64				rotr64 (u64 x, u32 r) { return (x >> (r&63)) | (x << ((0-r)&63)); }
	#define shl64(x,n)		((x)<<(n))
	#define shr64(x,n)		((x)>>(n))
	#define bswap32(x)		((rotl32((u32)(x)&0xFF00FF00UL,8))|(rotr32((u32)(x)&0x00FF00FFUL,8)))
	typedef union _ir_octet {u64 q;u32 d[2];} ir_octet;
	static u64				bswap64 (const u64 x) {ir_octet y,z;y.q=x,z.d[1]=bswap32(y.d[0]),z.d[0]=bswap32(y.d[1]);return z.q;}
#endif

#if !defined(ENRUPT32_TYPE)
	#if defined(i386)||defined(__i386__)||defined(_M_IX86)
		#define	ENRUPT32_TYPE	1		/* 0: generic u32, 1: MMX, 2: via u64 */
	#elif defined(__amd64__)||defined(__x86_64__)||defined(_M_IA64)||defined(_M_X64)
		#define	ENRUPT32_TYPE	0		/* 0: generic u32, 1: MMX (GCC only), 2: via u64 */
	#else								/* everything else */
		#define ENRUPT32_TYPE	0		/* 0: generic u32, 2: via u64 */
	#endif
#endif

#if !defined(ENRUPT64_TYPE)
	#if defined(i386)||defined(__i386__)||defined(_M_IX86)
		#define	ENRUPT64_TYPE	1		/* 0: generic u64, 1: SSE, 2: via u32 */
	#elif defined(__amd64__)||defined(__x86_64__)||defined(_M_IA64)||defined(_M_X64)
		#define	ENRUPT64_TYPE	0		/* 0: generic u64, 1: SSE, 2: via u32 */
	#else								/* everything else */
		#define ENRUPT64_TYPE	0		/* 0: generic u64, 2: via u32 */
	#endif
#endif

#if defined(__BYTE_ORDER)&&(__BYTE_ORDER==4321)||defined(BYTE_ORDER)&&(BYTE_ORDER==4321)||defined(sun)||defined(__sun)||defined(sparc)||defined(__sparc)||defined(__ppc__)
	#define ENRUPT_4321_BYTE_ORDER
#elif defined(__BYTE_ORDER)&&(__BYTE_ORDER==1234)||defined(BYTE_ORDER)&&(BYTE_ORDER==1234)||defined(i386)||defined(__i386__)||defined(__amd64__)||defined(__x86_64__)||defined(__vax__)||defined(__alpha)||defined(__ultrix)||defined(_M_IX86)||defined(_M_IA64)||defined(_M_X64)||defined(_M_ALPHA)
	#define ENRUPT_1234_BYTE_ORDER
#else
	#error Unknown endianness! Please define or disable this error and check at runtime.
#endif

#endif
