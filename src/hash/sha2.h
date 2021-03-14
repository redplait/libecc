/*
 *  Copyright (C) 2017 - This file is part of libecc project
 *
 *  Authors:
 *      Ryad BENADJILA <ryadbenadjila@gmail.com>
 *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
 *      Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
 *
 *  Contributors:
 *      Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
 *      Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
 *
 *  This software is licensed under a dual BSD and GPL v2 license.
 *  See LICENSE file at the root folder of the project.
 */
#ifndef __SHA2_H__
#define __SHA2_H__

#include "../words/words.h"

/* Useful primitives for handling 128-bit */

/* Add a 128-bit to a 64-bit element and store the result
 * in the input
 */
#define ADD_UINT128_UINT64(low,high,toadd) do {\
	(low) += (toadd);\
	if((low) < (toadd)){\
		(high)++;\
	}\
} while(0)

/* Store a 128-bit element in big endian format */
#define PUT_UINT128_BE(low,high,b,i) do {\
	PUT_UINT64_BE((high), (b), (i));\
	PUT_UINT64_BE((low), (b), (i)+8);\
} while(0)

/* Multiply a 128-bit element by 8 and store it in big endian
 * format
 */
#define PUT_MUL8_UINT128_BE(low,high,b,i) do {\
	u64 reslow, reshigh;\
	reslow = (low) << 3;\
	reshigh = ((low) >> 61) ^ ((high) << 3);\
	PUT_UINT128_BE(reslow,reshigh,(b),(i));\
} while(0)

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)				\
do {							\
	(n) =     ( ((u32) (b)[(i)	   ]) << 24 )	\
		| ( ((u32) (b)[(i) + 1]) << 16 )	\
		| ( ((u32) (b)[(i) + 2]) <<  8 )	\
		| ( ((u32) (b)[(i) + 3])       );	\
} while( 0 )
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)			\
do {						\
	(b)[(i)    ] = (u8) ( (n) >> 24 );	\
	(b)[(i) + 1] = (u8) ( (n) >> 16 );	\
	(b)[(i) + 2] = (u8) ( (n) >>  8 );	\
	(b)[(i) + 3] = (u8) ( (n)       );	\
} while( 0 )
#endif

/*
 * 64-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT64_BE
#define GET_UINT64_BE(n,b,i)				\
do {							\
    (n) = ( ((u64) (b)[(i)	   ]) << 56 )		\
	| ( ((u64) (b)[(i) + 1]) << 48 )		\
	| ( ((u64) (b)[(i) + 2]) << 40 )		\
	| ( ((u64) (b)[(i) + 3]) << 32 )		\
	| ( ((u64) (b)[(i) + 4]) << 24 )		\
	| ( ((u64) (b)[(i) + 5]) << 16 )		\
	| ( ((u64) (b)[(i) + 6]) <<  8 )		\
	| ( ((u64) (b)[(i) + 7])	    );		\
} while( 0 )
#endif /* GET_UINT64_BE */

#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n,b,i)		\
do {					\
    (b)[(i)    ] = (u8) ( (n) >> 56 );	\
    (b)[(i) + 1] = (u8) ( (n) >> 48 );	\
    (b)[(i) + 2] = (u8) ( (n) >> 40 );	\
    (b)[(i) + 3] = (u8) ( (n) >> 32 );	\
    (b)[(i) + 4] = (u8) ( (n) >> 24 );	\
    (b)[(i) + 5] = (u8) ( (n) >> 16 );	\
    (b)[(i) + 6] = (u8) ( (n) >>  8 );	\
    (b)[(i) + 7] = (u8) ( (n)       );	\
} while( 0 )
#endif /* PUT_UINT64_BE */

/* Useful macros for the SHA-2 core function  */
#define CH(x, y, z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define UPDATEW(w, i, sha_type) ((w)[(i)] = SIGMA_MIN1_##sha_type((w)[(i)-2]) + (w)[(i)-7] + SIGMA_MIN0_##sha_type((w)[(i)-15]) + (w)[(i)-16])

#define SHA2CORE(a, b, c, d, e, f, g, h, w, k, sha_word_type, sha_type) do {\
	sha_word_type t1, t2;\
	t1 = (h) + SIGMA_MAJ1_##sha_type((e)) + CH((e), (f), (g)) + (k) + (w);\
	t2 = SIGMA_MAJ0_##sha_type((a)) + MAJ((a), (b), (c));\
	(h) = (g);\
	(g) = (f);\
	(f) = (e);\
	(e) = (d) + t1;\
	(d) = (c);\
	(c) = (b);\
	(b) = (a);\
	(a) = t1 + t2;\
} while(0)

#if (defined(WITH_HASH_SHA224) || defined(WITH_HASH_SHA256))

/**********************************************/

/* SHA-224 and SHA-256 */
#define SHR_SHA256(x, n)       (((u32)(x)) >> (n))
#define ROTR_SHA256(x, n)      ((((u32)(x)) >> (n)) | (((u32)(x)) << (32-(n))))
#define SIGMA_MAJ0_SHA256(x)   (ROTR_SHA256(x, 2)  ^ ROTR_SHA256(x, 13) ^ ROTR_SHA256(x, 22))
#define SIGMA_MAJ1_SHA256(x)   (ROTR_SHA256(x, 6)  ^ ROTR_SHA256(x, 11) ^ ROTR_SHA256(x, 25))
#define SIGMA_MIN0_SHA256(x)   (ROTR_SHA256(x, 7)  ^ ROTR_SHA256(x, 18) ^ SHR_SHA256(x, 3))
#define SIGMA_MIN1_SHA256(x)   (ROTR_SHA256(x, 17) ^ ROTR_SHA256(x, 19) ^ SHR_SHA256(x, 10))
#define SHA2CORE_SHA256(a, b, c, d, e, f, g, h, w, k) \
	SHA2CORE(a, b, c, d, e, f, g, h, w, k, u32, SHA256)
#define UPDATEW_SHA256(w, i) UPDATEW(w, i, SHA256)
extern const u32 K_SHA256[];

/**********************************************/
#endif

#if (defined(WITH_HASH_SHA384) || defined(WITH_HASH_SHA512))

/**********************************************/

/* SHA-384 and SHA-512 */
#define SHR_SHA512(x, n)       (((u64)(x)) >> (n))
#define ROTR_SHA512(x, n)      ((((u64)(x)) >> (n)) | (((u64)(x)) << (64-(n))))
#define SIGMA_MAJ0_SHA512(x)   (ROTR_SHA512(x, 28) ^ ROTR_SHA512(x, 34) ^ ROTR_SHA512(x, 39))
#define SIGMA_MAJ1_SHA512(x)   (ROTR_SHA512(x, 14) ^ ROTR_SHA512(x, 18) ^ ROTR_SHA512(x, 41))
#define SIGMA_MIN0_SHA512(x)   (ROTR_SHA512(x, 1)  ^ ROTR_SHA512(x, 8)	^ SHR_SHA512(x, 7))
#define SIGMA_MIN1_SHA512(x)   (ROTR_SHA512(x, 19) ^ ROTR_SHA512(x, 61) ^ SHR_SHA512(x, 6))
#define SHA2CORE_SHA512(a, b, c, d, e, f, g, h, w, k) \
	SHA2CORE(a, b, c, d, e, f, g, h, w, k, u64, SHA512)
#define UPDATEW_SHA512(w, i) UPDATEW(w, i, SHA512)
extern const u64 K_SHA512[];

/**********************************************/
#endif

#endif /* __SHA2_H__ */
