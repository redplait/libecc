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
#include "../../lib_ecc_config.h"
#ifdef WITH_CURVE_SECP521R1

#include "ec_params_external.h"

#define CURVE_SECP521R1_P_BITLEN 521
#define CURVE_SECP521R1_Q_BITLEN 521

#ifndef SKIP_DATA

static const u8 secp521r1_p[] = {
	0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF
};

TO_EC_STR_PARAM(secp521r1_p);

static const u8 secp521r1_p_bitlen[] = { 0x02, 0x09 };

TO_EC_STR_PARAM(secp521r1_p_bitlen);

/*
 * Note: our multiprecision Montgomery mutiplication algorithm
 * fp_mul_redc1() expects R and R^2 used for prior redcification
 * to be power of B, the base in which we currently work, i.e.
 * the defined number of bits for our words. For primes which
 * have a common bitsize such as 256 and 512, which are a multiple
 * of 64, 32 and 16, the value of r and r^2 are alway same, no
 * matter the value of WORD_BYTES (i.e. no matter the base we
 * currently use). But for secp521r1, p being 521 bit long, r is
 * 2^576 mod p for 64 bits words, 2^544 mod p for 32 bits words
 * and 528 for 16 bit words. Hence the following specific
 * definitions for r and r^2 depending on words bitsize.
 */
#if (WORD_BYTES == 8)		/* 64-bit words */
static const u8 secp521r1_r[] = {
	0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const u8 secp521r1_r_square[] = {
	0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#elif (WORD_BYTES == 4)		/* 32-bit words */
static const u8 secp521r1_r[] = { 0x80, 0x00, 0x00 };

static const u8 secp521r1_r_square[] = {
	0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00
};
#elif (WORD_BYTES == 2)		/* 16-bit words */
static const u8 secp521r1_r[] = { 0x80 };
static const u8 secp521r1_r_square[] = { 0x40, 0x00 };
#else /* unknown word size */
#error "Unsupported word size"
#endif
TO_EC_STR_PARAM(secp521r1_r);
TO_EC_STR_PARAM(secp521r1_r_square);

static const u8 secp521r1_mpinv[] = { 0x01 };

TO_EC_STR_PARAM(secp521r1_mpinv);

#if (WORD_BYTES == 8)
static const u8 secp521r1_p_shift[] = {
	0x37
};

static const u8 secp521r1_p_normalized[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#elif (WORD_BYTES == 4)
static const u8 secp521r1_p_shift[] = {
	0x17
};

static const u8 secp521r1_p_normalized[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0x80, 0x00, 0x00
};
#elif (WORD_BYTES == 2)
static const u8 secp521r1_p_shift[] = {
	0x7
};

static const u8 secp521r1_p_normalized[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0x80
};
#else
#error "Unsupported word size"
#endif
TO_EC_STR_PARAM(secp521r1_p_shift);
TO_EC_STR_PARAM(secp521r1_p_normalized);

static const u8 secp521r1_p_reciprocal[] = {
	0x00
};

TO_EC_STR_PARAM(secp521r1_p_reciprocal);

static const u8 secp521r1_a[] = {
	0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFC
};

TO_EC_STR_PARAM(secp521r1_a);

static const u8 secp521r1_b[] = {
	0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C,
	0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85,
	0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3,
	0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1,
	0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E,
	0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1,
	0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C,
	0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50,
	0x3F, 0x00
};

TO_EC_STR_PARAM(secp521r1_b);

static const u8 secp521r1_npoints[] = {
	0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F,
	0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
	0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C,
	0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
	0x64, 0x09
};

TO_EC_STR_PARAM(secp521r1_npoints);

static const u8 secp521r1_gx[] = {
	0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04,
	0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66, 0x23, 0x95,
	0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F,
	0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D,
	0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7,
	0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF,
	0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A,
	0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5,
	0xBD, 0x66,
};

TO_EC_STR_PARAM(secp521r1_gx);

static const u8 secp521r1_gy[] = {
	0x01, 0x18, 0x39, 0x29, 0x6A, 0x78, 0x9A, 0x3B,
	0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4, 0x2C, 0x7D,
	0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49, 0x57, 0x9B,
	0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17, 0x27, 0x3E,
	0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99, 0x5E, 0xF4,
	0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD,
	0x07, 0x61, 0x35, 0x3C, 0x70, 0x86, 0xA2, 0x72,
	0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76, 0x9F, 0xD1,
	0x66, 0x50
};

TO_EC_STR_PARAM(secp521r1_gy);

static const u8 secp521r1_gz[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01
};

TO_EC_STR_PARAM(secp521r1_gz);

static const u8 secp521r1_order[] = {
	0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F,
	0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
	0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C,
	0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
	0x64, 0x09
};

TO_EC_STR_PARAM(secp521r1_order);

static const u8 secp521r1_order_bitlen[] = { 0x02, 0x09 };

TO_EC_STR_PARAM(secp521r1_order_bitlen);

static const u8 secp521r1_cofactor[] = { 0x01 };

TO_EC_STR_PARAM(secp521r1_cofactor);

#ifndef NO_OIDS
static const u8 secp521r1_oid[] = "1.3.132.0.35";
TO_EC_STR_PARAM(secp521r1_oid);
#endif /* !NO_OIDS */

#ifndef NO_NAMES
static const u8 secp521r1_name[] = "SECP521R1";
TO_EC_STR_PARAM(secp521r1_name);
#endif /* !NO_NAMES */

static const ec_str_params secp521r1_str_params = {
#ifdef WIN32
 &secp521r1_p_str_param,
 &secp521r1_p_bitlen_str_param,
 &secp521r1_r_str_param,
 &secp521r1_r_square_str_param,
 &secp521r1_mpinv_str_param,
 &secp521r1_p_shift_str_param,
 &secp521r1_p_normalized_str_param,
 &secp521r1_p_reciprocal_str_param,
 &secp521r1_a_str_param,
 &secp521r1_b_str_param,
 &secp521r1_npoints_str_param,
 &secp521r1_gx_str_param,
 &secp521r1_gy_str_param,
 &secp521r1_gz_str_param,
 &secp521r1_order_str_param,
 &secp521r1_order_bitlen_str_param,
 &secp521r1_cofactor_str_param,
#ifndef NO_OIDS
 &secp521r1_oid_str_param,
#endif /* !NO_OIDS */
#ifndef NO_NAMES
 &secp521r1_name_str_param,
#endif /* !NO_NAMES */
#else
	.p = &secp521r1_p_str_param,
	.p_bitlen = &secp521r1_p_bitlen_str_param,
	.r = &secp521r1_r_str_param,
	.r_square = &secp521r1_r_square_str_param,
	.mpinv = &secp521r1_mpinv_str_param,
	.p_shift = &secp521r1_p_shift_str_param,
	.p_normalized = &secp521r1_p_normalized_str_param,
	.p_reciprocal = &secp521r1_p_reciprocal_str_param,
	.a = &secp521r1_a_str_param,
	.b = &secp521r1_b_str_param,
	.npoints = &secp521r1_npoints_str_param,
	.gx = &secp521r1_gx_str_param,
	.gy = &secp521r1_gy_str_param,
	.gz = &secp521r1_gz_str_param,
	.order = &secp521r1_order_str_param,
	.order_bitlen = &secp521r1_order_bitlen_str_param,
	.cofactor = &secp521r1_cofactor_str_param,
	.oid = &secp521r1_oid_str_param,
	.name = &secp521r1_name_str_param,
#endif /* WIN32 */
};
#endif /* !SKIP_DATA */

/*
 * Compute max bit length of all curves for p and q
 */
#ifndef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN    0
#endif
#if (CURVES_MAX_P_BIT_LEN < CURVE_SECP521R1_P_BITLEN)
#undef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN CURVE_SECP521R1_P_BITLEN
#endif
#ifndef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN    0
#endif
#if (CURVES_MAX_Q_BIT_LEN < CURVE_SECP521R1_Q_BITLEN)
#undef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN CURVE_SECP521R1_Q_BITLEN
#endif

#endif /* WITH_CURVE_SECP521R1 */
