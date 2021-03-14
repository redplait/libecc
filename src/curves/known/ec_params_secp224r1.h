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
#ifdef WITH_CURVE_SECP224R1

#include "ec_params_external.h"

#define CURVE_SECP224R1_P_BITLEN 224
#define CURVE_SECP224R1_Q_BITLEN 224

#ifndef SKIP_DATA

static const u8 secp224r1_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01
};

TO_EC_STR_PARAM(secp224r1_p);

static const u8 secp224r1_p_bitlen[] = { 0xE0 };

TO_EC_STR_PARAM(secp224r1_p_bitlen);

#if (WORD_BYTES == 8)		/* 64-bit words */
static const u8 secp224r1_p_normalized[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
};

static const u8 secp224r1_p_shift[] = {
	0x20
};

static const u8 secp224r1_r[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
};

static const u8 secp224r1_r_square[] = {
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
};

static const u8 secp224r1_mpinv[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
#elif (WORD_BYTES == 4)		/* 32-bit words */
static const u8 secp224r1_p_normalized[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01
};

static const u8 secp224r1_p_shift[] = {
	0x00
};

static const u8 secp224r1_r[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff
};

static const u8 secp224r1_r_square[] = {
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01
};

static const u8 secp224r1_mpinv[] = {
	0xff, 0xff, 0xff, 0xff
};
#elif (WORD_BYTES == 2)		/* 16-bit words */
static const u8 secp224r1_p_normalized[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01
};

static const u8 secp224r1_p_shift[] = {
	0x00
};

static const u8 secp224r1_r[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff
};

static const u8 secp224r1_r_square[] = {
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01
};

static const u8 secp224r1_mpinv[] = {
	0xff, 0xff
};
#else /* unknown word size */
#error "Unsupported word size"
#endif
TO_EC_STR_PARAM(secp224r1_r);
TO_EC_STR_PARAM(secp224r1_r_square);
TO_EC_STR_PARAM(secp224r1_p_normalized);
TO_EC_STR_PARAM(secp224r1_mpinv);
TO_EC_STR_PARAM(secp224r1_p_shift);

static const u8 secp224r1_p_reciprocal[] = {
	0x00
};

TO_EC_STR_PARAM(secp224r1_p_reciprocal);

static const u8 secp224r1_a[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE
};

TO_EC_STR_PARAM(secp224r1_a);

static const u8 secp224r1_b[] = {
	0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB,
	0xF5, 0x41, 0x32, 0x56, 0x50, 0x44, 0xB0, 0xB7,
	0xD7, 0xBF, 0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43,
	0x23, 0x55, 0xFF, 0xB4
};

TO_EC_STR_PARAM(secp224r1_b);

static const u8 secp224r1_npoints[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x16, 0xA2,
	0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45,
	0x5C, 0x5C, 0x2A, 0x3D
};

TO_EC_STR_PARAM(secp224r1_npoints);

static const u8 secp224r1_gx[] = {
	0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F,
	0x32, 0x13, 0x90, 0xB9, 0x4A, 0x03, 0xC1, 0xD3,
	0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6,
	0x11, 0x5C, 0x1D, 0x21
};

TO_EC_STR_PARAM(secp224r1_gx);

static const u8 secp224r1_gy[] = {
	0xBD, 0x37, 0x63, 0x88, 0xB5, 0xF7, 0x23, 0xFB,
	0x4C, 0x22, 0xDF, 0xE6, 0xCD, 0x43, 0x75, 0xA0,
	0x5A, 0x07, 0x47, 0x64, 0x44, 0xD5, 0x81, 0x99,
	0x85, 0x00, 0x7E, 0x34
};

TO_EC_STR_PARAM(secp224r1_gy);

static const u8 secp224r1_gz[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01
};

TO_EC_STR_PARAM(secp224r1_gz);

static const u8 secp224r1_order[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x16, 0xA2,
	0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45,
	0x5C, 0x5C, 0x2A, 0x3D
};

TO_EC_STR_PARAM(secp224r1_order);

static const u8 secp224r1_order_bitlen[] = { 0xE0 };

TO_EC_STR_PARAM(secp224r1_order_bitlen);

static const u8 secp224r1_cofactor[] = { 0x01 };

TO_EC_STR_PARAM(secp224r1_cofactor);

#ifndef NO_OIDS
static const u8 secp224r1_oid[] = "1.3.132.0.33";
TO_EC_STR_PARAM(secp224r1_oid);
#endif /* !NO_OIDS */

#ifndef NO_NAMES
static const u8 secp224r1_name[] = "SECP224R1";
TO_EC_STR_PARAM(secp224r1_name);
#endif /* !NO_NAMES */

static const ec_str_params secp224r1_str_params = {
#ifdef WIN32
 &secp224r1_p_str_param,
 &secp224r1_p_bitlen_str_param,
 &secp224r1_r_str_param,
 &secp224r1_r_square_str_param,
 &secp224r1_mpinv_str_param,
 &secp224r1_p_shift_str_param,
 &secp224r1_p_normalized_str_param,
 &secp224r1_p_reciprocal_str_param,
 &secp224r1_a_str_param,
 &secp224r1_b_str_param,
 &secp224r1_npoints_str_param,
 &secp224r1_gx_str_param,
 &secp224r1_gy_str_param,
 &secp224r1_gz_str_param,
 &secp224r1_order_str_param,
 &secp224r1_order_bitlen_str_param,
 &secp224r1_cofactor_str_param,
#ifndef NO_OIDS
 &secp224r1_oid_str_param,
#endif /* !NO_OIDS */
#ifndef NO_NAMES
 &secp224r1_name_str_param,
#endif /* !NO_NAMES */
#else
	.p = &secp224r1_p_str_param,
	.p_bitlen = &secp224r1_p_bitlen_str_param,
	.r = &secp224r1_r_str_param,
	.r_square = &secp224r1_r_square_str_param,
	.mpinv = &secp224r1_mpinv_str_param,
	.p_shift = &secp224r1_p_shift_str_param,
	.p_normalized = &secp224r1_p_normalized_str_param,
	.p_reciprocal = &secp224r1_p_reciprocal_str_param,
	.a = &secp224r1_a_str_param,
	.b = &secp224r1_b_str_param,
	.npoints = &secp224r1_npoints_str_param,
	.gx = &secp224r1_gx_str_param,
	.gy = &secp224r1_gy_str_param,
	.gz = &secp224r1_gz_str_param,
	.order = &secp224r1_order_str_param,
	.order_bitlen = &secp224r1_order_bitlen_str_param,
	.cofactor = &secp224r1_cofactor_str_param,
	.oid = &secp224r1_oid_str_param,
	.name = &secp224r1_name_str_param,
#endif /* WIN32 */
};
#endif /* !SKIP_DATA */

/*
 * Compute max bit length of all curves for p and q
 */
#if (CURVES_MAX_P_BIT_LEN < CURVE_SECP224R1_P_BITLEN)
#undef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN CURVE_SECP224R1_P_BITLEN
#endif
#if (CURVES_MAX_Q_BIT_LEN < CURVE_SECP224R1_Q_BITLEN)
#undef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN CURVE_SECP224R1_Q_BITLEN
#endif

#endif /* WITH_CURVE_SECP224R1 */
