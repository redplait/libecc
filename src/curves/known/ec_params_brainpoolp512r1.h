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
#ifdef WITH_CURVE_BRAINPOOLP512R1

#ifndef __EC_PARAMS_BRAINPOOLP512R1_H__
#define __EC_PARAMS_BRAINPOOLP512R1_H__
#include "ec_params_external.h"

static const u8 brainpoolp512r1_p[] = {
	0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B,
	0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07,
	0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
	0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71,
	0x7D, 0x4D, 0x9B, 0x00, 0x9B, 0xC6, 0x68, 0x42,
	0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
	0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85,
	0x28, 0xAA, 0x60, 0x56, 0x58, 0x3A, 0x48, 0xF3
};

TO_EC_STR_PARAM(brainpoolp512r1_p);

#define CURVE_BRAINPOOLP512R1_P_BITLEN 512
static const u8 brainpoolp512r1_p_bitlen[] = { 0x02, 0x00 };

TO_EC_STR_PARAM(brainpoolp512r1_p_bitlen);

static const u8 brainpoolp512r1_r[] = {
	0x55, 0x22, 0x62, 0x47, 0x24, 0x16, 0x3b, 0x74,
	0xc0, 0x2b, 0x19, 0x51, 0xcc, 0x36, 0x03, 0xf8,
	0x34, 0xcf, 0x72, 0x4c, 0x4c, 0x36, 0x2d, 0xf1,
	0x29, 0x9c, 0x63, 0x35, 0x8f, 0xcc, 0xf7, 0x8e,
	0x82, 0xb2, 0x64, 0xff, 0x64, 0x39, 0x97, 0xbd,
	0x51, 0x32, 0x5e, 0xd5, 0x19, 0x5c, 0x7f, 0x19,
	0xd7, 0x7e, 0x00, 0xd0, 0xd2, 0x7d, 0x39, 0x7a,
	0xd7, 0x55, 0x9f, 0xa9, 0xa7, 0xc5, 0xb7, 0x0d
};

TO_EC_STR_PARAM(brainpoolp512r1_r);

static const u8 brainpoolp512r1_r_square[] = {
	0x3c, 0x4c, 0x9d, 0x05, 0xa9, 0xff, 0x64, 0x50,
	0x20, 0x2e, 0x19, 0x40, 0x20, 0x56, 0xee, 0xcc,
	0xa1, 0x6d, 0xaa, 0x5f, 0xd4, 0x2b, 0xff, 0x83,
	0x19, 0x48, 0x6f, 0xd8, 0xd5, 0x89, 0x80, 0x57,
	0xe0, 0xc1, 0x9a, 0x77, 0x83, 0x51, 0x4a, 0x25,
	0x53, 0xb7, 0xf9, 0xbc, 0x90, 0x5a, 0xff, 0xd3,
	0x79, 0x3f, 0xb1, 0x30, 0x27, 0x15, 0x79, 0x05,
	0x49, 0xad, 0x14, 0x4a, 0x61, 0x58, 0xf2, 0x05
};

TO_EC_STR_PARAM(brainpoolp512r1_r_square);

/*
 * mpinv is -p^-1 mod 2^(bitsizeof(hword_t)), this means it depends
 * on word size.
 */
static const u8 brainpoolp512r1_mpinv[] = {
	0x83, 0x9b, 0x32, 0x20, 0x7d, 0x89, 0xef, 0xc5
};

TO_EC_STR_PARAM(brainpoolp512r1_mpinv);

static const u8 brainpoolp512r1_p_shift[] = {
	0x00
};

TO_EC_STR_PARAM(brainpoolp512r1_p_shift);

#if (WORD_BYTES == 8)		/* 64-bit words */
static const u8 brainpoolp512r1_p_reciprocal[] = {
	0x7f, 0x8d, 0x7f, 0x4e, 0xd6, 0xda, 0xeb, 0x8a
};
#elif (WORD_BYTES == 4)		/* 32-bit words */
static const u8 brainpoolp512r1_p_reciprocal[] = {
	0x7f, 0x8d, 0x7f, 0x4e
};
#elif (WORD_BYTES == 2)		/* 16-bit words */
static const u8 brainpoolp512r1_p_reciprocal[] = {
	0x7f, 0x8d
};
#else /* unknown word size */
#error "Unsupported word size"
#endif
TO_EC_STR_PARAM(brainpoolp512r1_p_reciprocal);

static const u8 brainpoolp512r1_a[] = {
	0x78, 0x30, 0xA3, 0x31, 0x8B, 0x60, 0x3B, 0x89,
	0xE2, 0x32, 0x71, 0x45, 0xAC, 0x23, 0x4C, 0xC5,
	0x94, 0xCB, 0xDD, 0x8D, 0x3D, 0xF9, 0x16, 0x10,
	0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC,
	0x2D, 0xED, 0x5D, 0x5A, 0xA8, 0x25, 0x3A, 0xA1,
	0x0A, 0x2E, 0xF1, 0xC9, 0x8B, 0x9A, 0xC8, 0xB5,
	0x7F, 0x11, 0x17, 0xA7, 0x2B, 0xF2, 0xC7, 0xB9,
	0xE7, 0xC1, 0xAC, 0x4D, 0x77, 0xFC, 0x94, 0xCA
};

TO_EC_STR_PARAM(brainpoolp512r1_a);

static const u8 brainpoolp512r1_b[] = {
	0x3D, 0xF9, 0x16, 0x10, 0xA8, 0x34, 0x41, 0xCA,
	0xEA, 0x98, 0x63, 0xBC, 0x2D, 0xED, 0x5D, 0x5A,
	0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9,
	0x8B, 0x9A, 0xC8, 0xB5, 0x7F, 0x11, 0x17, 0xA7,
	0x2B, 0xF2, 0xC7, 0xB9, 0xE7, 0xC1, 0xAC, 0x4D,
	0x77, 0xFC, 0x94, 0xCA, 0xDC, 0x08, 0x3E, 0x67,
	0x98, 0x40, 0x50, 0xB7, 0x5E, 0xBA, 0xE5, 0xDD,
	0x28, 0x09, 0xBD, 0x63, 0x80, 0x16, 0xF7, 0x23
};

TO_EC_STR_PARAM(brainpoolp512r1_b);

static const u8 brainpoolp512r1_npoints[] = {
	0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B,
	0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07,
	0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
	0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x70,
	0x55, 0x3E, 0x5C, 0x41, 0x4C, 0xA9, 0x26, 0x19,
	0x41, 0x86, 0x61, 0x19, 0x7F, 0xAC, 0x10, 0x47,
	0x1D, 0xB1, 0xD3, 0x81, 0x08, 0x5D, 0xDA, 0xDD,
	0xB5, 0x87, 0x96, 0x82, 0x9C, 0xA9, 0x00, 0x69
};

TO_EC_STR_PARAM(brainpoolp512r1_npoints);

static const u8 brainpoolp512r1_gx[] = {
	0x81, 0xAE, 0xE4, 0xBD, 0xD8, 0x2E, 0xD9, 0x64,
	0x5A, 0x21, 0x32, 0x2E, 0x9C, 0x4C, 0x6A, 0x93,
	0x85, 0xED, 0x9F, 0x70, 0xB5, 0xD9, 0x16, 0xC1,
	0xB4, 0x3B, 0x62, 0xEE, 0xF4, 0xD0, 0x09, 0x8E,
	0xFF, 0x3B, 0x1F, 0x78, 0xE2, 0xD0, 0xD4, 0x8D,
	0x50, 0xD1, 0x68, 0x7B, 0x93, 0xB9, 0x7D, 0x5F,
	0x7C, 0x6D, 0x50, 0x47, 0x40, 0x6A, 0x5E, 0x68,
	0x8B, 0x35, 0x22, 0x09, 0xBC, 0xB9, 0xF8, 0x22,
};

TO_EC_STR_PARAM(brainpoolp512r1_gx);

static const u8 brainpoolp512r1_gy[] = {
	0x7D, 0xDE, 0x38, 0x5D, 0x56, 0x63, 0x32, 0xEC,
	0xC0, 0xEA, 0xBF, 0xA9, 0xCF, 0x78, 0x22, 0xFD,
	0xF2, 0x09, 0xF7, 0x00, 0x24, 0xA5, 0x7B, 0x1A,
	0xA0, 0x00, 0xC5, 0x5B, 0x88, 0x1F, 0x81, 0x11,
	0xB2, 0xDC, 0xDE, 0x49, 0x4A, 0x5F, 0x48, 0x5E,
	0x5B, 0xCA, 0x4B, 0xD8, 0x8A, 0x27, 0x63, 0xAE,
	0xD1, 0xCA, 0x2B, 0x2F, 0xA8, 0xF0, 0x54, 0x06,
	0x78, 0xCD, 0x1E, 0x0F, 0x3A, 0xD8, 0x08, 0x92
};

TO_EC_STR_PARAM(brainpoolp512r1_gy);

static const u8 brainpool512r1_gz[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

TO_EC_STR_PARAM(brainpool512r1_gz);

static const u8 brainpoolp512r1_order[] = {
	0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B,
	0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07,
	0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
	0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x70,
	0x55, 0x3E, 0x5C, 0x41, 0x4C, 0xA9, 0x26, 0x19,
	0x41, 0x86, 0x61, 0x19, 0x7F, 0xAC, 0x10, 0x47,
	0x1D, 0xB1, 0xD3, 0x81, 0x08, 0x5D, 0xDA, 0xDD,
	0xB5, 0x87, 0x96, 0x82, 0x9C, 0xA9, 0x00, 0x69
};

TO_EC_STR_PARAM(brainpoolp512r1_order);

#define CURVE_BRAINPOOLP512R1_Q_BITLEN 512
static const u8 brainpoolp512r1_order_bitlen[] = { 0x02, 0x00 };

TO_EC_STR_PARAM(brainpoolp512r1_order_bitlen);

static const u8 brainpoolp512r1_cofactor[] = { 0x01 };

TO_EC_STR_PARAM(brainpoolp512r1_cofactor);

static const u8 brainpoolp512r1_oid[] = "1.3.36.3.3.2.8.1.1.13";
TO_EC_STR_PARAM(brainpoolp512r1_oid);

#ifndef NO_NAMES
static const u8 brainpoolp512r1_name[] = "BRAINPOOLP512R1";
TO_EC_STR_PARAM(brainpoolp512r1_name);
#endif /* !NO_NAMES */

static const ec_str_params brainpoolp512r1_str_params = {
#ifdef WIN32
  &brainpoolp512r1_p_str_param,
  &brainpoolp512r1_p_bitlen_str_param,
  &brainpoolp512r1_r_str_param,
  &brainpoolp512r1_r_square_str_param,
  &brainpoolp512r1_mpinv_str_param,
  &brainpoolp512r1_p_shift_str_param,
  &brainpoolp512r1_p_str_param,
  &brainpoolp512r1_p_reciprocal_str_param,
  &brainpoolp512r1_a_str_param,
  &brainpoolp512r1_b_str_param,
  &brainpoolp512r1_npoints_str_param,
  &brainpoolp512r1_gx_str_param,
  &brainpoolp512r1_gy_str_param,
  &brainpool512r1_gz_str_param,
  &brainpoolp512r1_order_str_param,
  &brainpoolp512r1_order_bitlen_str_param,
  &brainpoolp512r1_cofactor_str_param,
  &brainpoolp512r1_oid_str_param,
#ifndef NO_NAMES
  &brainpoolp512r1_name_str_param,
#endif /* NO_NAMES */
#else
	.p = &brainpoolp512r1_p_str_param,
	.p_bitlen = &brainpoolp512r1_p_bitlen_str_param,
	.r = &brainpoolp512r1_r_str_param,
	.r_square = &brainpoolp512r1_r_square_str_param,
	.mpinv = &brainpoolp512r1_mpinv_str_param,
	.p_shift = &brainpoolp512r1_p_shift_str_param,
	.p_normalized = &brainpoolp512r1_p_str_param,
	.p_reciprocal = &brainpoolp512r1_p_reciprocal_str_param,
	.a = &brainpoolp512r1_a_str_param,
	.b = &brainpoolp512r1_b_str_param,
	.npoints = &brainpoolp512r1_npoints_str_param,
	.gx = &brainpoolp512r1_gx_str_param,
	.gy = &brainpoolp512r1_gy_str_param,
	.gz = &brainpool512r1_gz_str_param,
	.order = &brainpoolp512r1_order_str_param,
	.order_bitlen = &brainpoolp512r1_order_bitlen_str_param,
	.cofactor = &brainpoolp512r1_cofactor_str_param,
	.oid = &brainpoolp512r1_oid_str_param,
	.name = &brainpoolp512r1_name_str_param,
#endif /* WIN32 */
};

/*
 * Compute max bit length of all curves for p and q
 */
#ifndef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN    0
#endif
#if (CURVES_MAX_P_BIT_LEN < CURVE_BRAINPOOLP512R1_P_BITLEN)
#undef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN CURVE_BRAINPOOLP512R1_P_BITLEN
#endif
#ifndef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN    0
#endif
#if (CURVES_MAX_Q_BIT_LEN < CURVE_BRAINPOOLP512R1_Q_BITLEN)
#undef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN CURVE_BRAINPOOLP512R1_Q_BITLEN
#endif

#endif /* __EC_PARAMS_BRAINPOOLP512R1_H__ */
#endif /* WITH_CURVE_BRAINPOOLP512R1 */
