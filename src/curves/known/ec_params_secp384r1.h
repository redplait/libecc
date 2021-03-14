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
#ifdef WITH_CURVE_SECP384R1

#include "ec_params_external.h"

#define CURVE_SECP384R1_P_BITLEN 384
#define CURVE_SECP384R1_Q_BITLEN 384

#ifndef SKIP_DATA

static const u8 secp384r1_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

TO_EC_STR_PARAM(secp384r1_p);

static const u8 secp384r1_p_bitlen[] = { 0x01, 0x80 };

TO_EC_STR_PARAM(secp384r1_p_bitlen);

static const u8 secp384r1_r[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
};

TO_EC_STR_PARAM(secp384r1_r);

static const u8 secp384r1_r_square[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x01
};

TO_EC_STR_PARAM(secp384r1_r_square);

#if (WORD_BYTES == 8)		/* 64-bit words */
static const u8 secp384r1_mpinv[] = {
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01
};
#elif (WORD_BYTES == 4)		/* 32-bit words */
static const u8 secp384r1_mpinv[] = {
	0x00, 0x00, 0x00, 0x01
};
#elif (WORD_BYTES == 2)		/* 16-bit words */
static const u8 secp384r1_mpinv[] = {
	0x00, 0x01
};
#else /* unknown word size */
#error "Unsupported word size"
#endif

TO_EC_STR_PARAM(secp384r1_mpinv);

static const u8 secp384r1_p_shift[] = {
	0x00
};

TO_EC_STR_PARAM(secp384r1_p_shift);

static const u8 secp384r1_p_reciprocal[] = {
	0x00
};

TO_EC_STR_PARAM(secp384r1_p_reciprocal);

static const u8 secp384r1_a[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC,
};

TO_EC_STR_PARAM(secp384r1_a);

static const u8 secp384r1_b[] = {
	0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
	0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
	0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
	0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
	0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
	0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF
};

TO_EC_STR_PARAM(secp384r1_b);

static const u8 secp384r1_npoints[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
	0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
	0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
};

TO_EC_STR_PARAM(secp384r1_npoints);

static const u8 secp384r1_gx[] = {
	0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37,
	0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
	0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
	0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
	0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C,
	0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7
};

TO_EC_STR_PARAM(secp384r1_gx);

static const u8 secp384r1_gy[] = {
	0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F,
	0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
	0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C,
	0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
	0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D,
	0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F
};

TO_EC_STR_PARAM(secp384r1_gy);

static const u8 secp384r1_gz[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

TO_EC_STR_PARAM(secp384r1_gz);

static const u8 secp384r1_order[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
	0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
	0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
};

TO_EC_STR_PARAM(secp384r1_order);

static const u8 secp384r1_order_bitlen[] = { 0x01, 0x80 };

TO_EC_STR_PARAM(secp384r1_order_bitlen);

static const u8 secp384r1_cofactor[] = { 0x01 };

TO_EC_STR_PARAM(secp384r1_cofactor);

#ifndef NO_OIDS
static const u8 secp384r1_oid[] = "1.3.132.0.34";
TO_EC_STR_PARAM(secp384r1_oid);
#endif /* !NO_OIDS */

#ifndef NO_NAMES
static const u8 secp384r1_name[] = "SECP384R1";
TO_EC_STR_PARAM(secp384r1_name);
#endif /* !NO_NAMES */

static const ec_str_params secp384r1_str_params = {
#ifdef WIN32
 &secp384r1_p_str_param,
 &secp384r1_p_bitlen_str_param,
 &secp384r1_r_str_param,
 &secp384r1_r_square_str_param,
 &secp384r1_mpinv_str_param,
 &secp384r1_p_shift_str_param,
 &secp384r1_p_str_param,
 &secp384r1_p_reciprocal_str_param,
 &secp384r1_a_str_param,
 &secp384r1_b_str_param,
 &secp384r1_npoints_str_param,
 &secp384r1_gx_str_param,
 &secp384r1_gy_str_param,
 &secp384r1_gz_str_param,
 &secp384r1_order_str_param,
 &secp384r1_order_bitlen_str_param,
 &secp384r1_cofactor_str_param,
#ifndef NO_OIDS
 &secp384r1_oid_str_param,
#endif /* !NO_OIDS */
#ifndef NO_NAMES
 &secp384r1_name_str_param,
#endif /* !NO_NAMES */
#else
	.p = &secp384r1_p_str_param,
	.p_bitlen = &secp384r1_p_bitlen_str_param,
	.r = &secp384r1_r_str_param,
	.r_square = &secp384r1_r_square_str_param,
	.mpinv = &secp384r1_mpinv_str_param,
	.p_shift = &secp384r1_p_shift_str_param,
	.p_normalized = &secp384r1_p_str_param,
	.p_reciprocal = &secp384r1_p_reciprocal_str_param,
	.a = &secp384r1_a_str_param,
	.b = &secp384r1_b_str_param,
	.npoints = &secp384r1_npoints_str_param,
	.gx = &secp384r1_gx_str_param,
	.gy = &secp384r1_gy_str_param,
	.gz = &secp384r1_gz_str_param,
	.order = &secp384r1_order_str_param,
	.order_bitlen = &secp384r1_order_bitlen_str_param,
	.cofactor = &secp384r1_cofactor_str_param,
	.oid = &secp384r1_oid_str_param,
	.name = &secp384r1_name_str_param,
#endif /* WIN32 */
};
#endif /* !SKIP_DATA */

/*
 * Compute max bit length of all curves for p and q
 */
#ifndef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN    0
#endif
#if (CURVES_MAX_P_BIT_LEN < CURVE_SECP384R1_P_BITLEN)
#undef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN CURVE_SECP384R1_P_BITLEN
#endif
#ifndef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN    0
#endif
#if (CURVES_MAX_Q_BIT_LEN < CURVE_SECP384R1_Q_BITLEN)
#undef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN CURVE_SECP384R1_Q_BITLEN
#endif

#endif /* WITH_CURVE_SECP384R1 */
