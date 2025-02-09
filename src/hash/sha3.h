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
#ifndef __SHA3_H__
#define __SHA3_H__

#include "../words/words.h"

#define _KECCAK_ROTL_(x, y) (((x) << (y)) | ((x) >> ((sizeof(u64) * 8) - (y))))

/* We handle the case where one of the shifts is more than 64-bit: in this
 * case, behaviour is undefined as per ANSI C definition. In this case, we
 * return the untouched input.
 */
#define KECCAK_ROTL(x, y) ((((y) < (sizeof(u64) * 8)) && ((y) > 0)) ? (_KECCAK_ROTL_(x, y)) : (x))

/*
 * Round transformation of the state. Notations are the 
 * same as the ones used in:
 * http://keccak.noekeon.org/specs_summary.html
 */
#define KECCAK_WORD_LOG 6
#define KECCAK_ROUNDS   (12 + (2 * KECCAK_WORD_LOG))
#define KECCAK_SLICES   5

extern const u64 keccak_rc[KECCAK_ROUNDS];

static const u8 keccak_rot[KECCAK_SLICES][KECCAK_SLICES] = 
{
	{  0, 36,  3, 41, 18 },
	{  1, 44, 10, 45,  2 },
	{ 62,  6, 43, 15, 61 },
	{ 28, 55, 25, 21, 56 },
	{ 27, 20, 39,  8, 14 },
};


/* Macro to handle endianness conversion */
#define SWAP64_Idx(a)   ((sizeof(u64) * ((a) / sizeof(u64))) + (sizeof(u64) - 1 - ((a) % sizeof(u64))))

#define Idx_slices(x, y)	((x) + (KECCAK_SLICES * (y)))
#define Idx(A, x, y)    	((A)[Idx_slices(x, y)])

#define KECCAKROUND(A, RC) do {	                                                        \
        int x, y;                                                                       \
        u64 tmp;                                                                        \
        /* Temporary B, C and D arrays */                                               \
        u64 BCD[KECCAK_SLICES * KECCAK_SLICES];                                         \
        /* Theta step */                                                                \
        for(x = 0; x < KECCAK_SLICES; x++){                                             \
                Idx(BCD, x, 0) = Idx(A, x, 0) ^ Idx(A, x, 1) ^ Idx(A, x, 2) ^           \
                                 Idx(A, x, 3) ^ Idx(A, x, 4);                           \
        }                                                                               \
        for(x = 0; x < KECCAK_SLICES; x++){                                             \
                tmp = Idx(BCD, (x + 4) % 5, 0) ^                                        \
                      KECCAK_ROTL(Idx(BCD, (x + 1) % 5, 0), 1);                         \
                for(y = 0; y < KECCAK_SLICES; y++){                                     \
                        Idx(A, x, y) ^= tmp;                                            \
                }                                                                       \
        }                                                                               \
        /* Rho and Pi steps */                                                          \
        for(x = 0; x < KECCAK_SLICES; x++){                                             \
                for(y = 0; y < KECCAK_SLICES; y++){                                     \
                        Idx(BCD, y, ((2*x)+(3*y)) % 5) =                                \
                        KECCAK_ROTL(Idx(A, x, y), keccak_rot[x][y]);           		\
                }                                                                       \
        }                                                                               \
        /* Chi step */                                                                  \
        for(x = 0; x < KECCAK_SLICES; x++){                                             \
                for(y = 0; y < KECCAK_SLICES; y++){                                     \
                        Idx(A, x, y) = Idx(BCD, x, y) ^                                 \
                                (~Idx(BCD, (x+1) % 5, y) & Idx(BCD, (x+2)%5, y));       \
                }                                                                       \
        }                                                                               \
        /* Iota step */                                                                 \
        Idx(A, 0, 0) ^= (RC);                                                           \
} while(0)

#define KECCAKF(A) do {		               		        	                \
        int round;                                       	        	        \
        for(round = 0; round < KECCAK_ROUNDS; round++){                         	\
                KECCAKROUND(A, keccak_rc[round]); 	                    		\
        }                                                              			\
} while(0)


typedef enum {
	SHA3_LITTLE = 0,
	SHA3_BIG = 1,
} sha3_endianness;
/*
 * Generic context for all SHA3 instances. Only difference is digest size
 * value, initialized in init() call and used in finalize().
 */
typedef struct sha3_context_ {
        u8 sha3_digest_size;
        u8 sha3_block_size;
	sha3_endianness sha3_endian;
        /* Local index, useful for the absorbing phase */
        u64 sha3_idx;
        /* Keccak's state, viewed as a bi-dimensional array */
        u64 sha3_state[KECCAK_SLICES * KECCAK_SLICES];
} sha3_context;


void _sha3_init(sha3_context *ctx, u8 digest_size);
void _sha3_update(sha3_context *ctx, const u8 *buf, u32 buflen);
void _sha3_finalize(sha3_context *ctx, u8 *output);

#endif /* __SHA3_H__ */
