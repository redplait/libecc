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
#ifdef WITH_CURVE_BRAINPOOLP384R1

#ifndef __EC_PARAMS_BRAINPOOLP384R1_H__
#define __EC_PARAMS_BRAINPOOLP384R1_H__
#include "ec_params_external.h"

static const u8 brainpoolp384r1_p[] = {
	0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28,
	0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF,
	0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4,
	0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23,
	0xAC, 0xD3, 0xA7, 0x29, 0x90, 0x1D, 0x1A, 0x71,
	0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53
};

TO_EC_STR_PARAM(brainpoolp384r1_p);

#define CURVE_BRAINPOOLP384R1_P_BITLEN 384
static const u8 brainpoolp384r1_p_bitlen[] = { 0x01, 0x80 };

TO_EC_STR_PARAM(brainpoolp384r1_p_bitlen);

static const u8 brainpoolp384r1_r[] = {
	0x73, 0x46, 0xE1, 0x7D, 0x5C, 0xC7, 0x92, 0xD7,
	0xF0, 0xA2, 0x90, 0x81, 0xAF, 0x19, 0xBE, 0x20,
	0xEA, 0xD0, 0x8E, 0xF6, 0x12, 0xAB, 0xA9, 0x4B,
	0xED, 0x4E, 0x25, 0xE6, 0x80, 0x48, 0xEE, 0xDC,
	0x53, 0x2C, 0x58, 0xD6, 0x6F, 0xE2, 0xE5, 0x8E,
	0x78, 0xB8, 0xFF, 0xEC, 0xCE, 0xF8, 0x13, 0xAD
};

TO_EC_STR_PARAM(brainpoolp384r1_r);

static const u8 brainpoolp384r1_r_square[] = {
	0x36, 0xBF, 0x68, 0x83, 0x17, 0x8D, 0xF8, 0x42,
	0xD5, 0xC6, 0xEF, 0x3B, 0xA5, 0x7E, 0x05, 0x2C,
	0x62, 0x14, 0x01, 0x91, 0x99, 0x18, 0xD5, 0xAF,
	0x8E, 0x28, 0xF9, 0x9C, 0xC9, 0x94, 0x08, 0x99,
	0x53, 0x52, 0x83, 0x34, 0x3D, 0x7F, 0xD9, 0x65,
	0x08, 0x7C, 0xEF, 0xFF, 0x40, 0xB6, 0x4B, 0xDE
};

TO_EC_STR_PARAM(brainpoolp384r1_r_square);

#if (WORD_BYTES == 8)		/* 64-bit words */
static const u8 brainpoolp384r1_mpinv[] = {
	0x9A, 0x6E, 0xA9, 0x6C, 0xEA, 0x9E, 0xC8, 0x25
};
#elif (WORD_BYTES == 4)		/* 32-bit words */
static const u8 brainpoolp384r1_mpinv[] = {
	0xEA, 0x9E, 0xC8, 0x25
};
#elif (WORD_BYTES == 2)		/* 16-bit words */
static const u8 brainpoolp384r1_mpinv[] = {
	0xC8, 0x25
};
#else /* unknown word size */
#error "Unsupported word size"
#endif

TO_EC_STR_PARAM(brainpoolp384r1_mpinv);

static const u8 brainpoolp384r1_p_shift[] = {
	0x00
};

TO_EC_STR_PARAM(brainpoolp384r1_p_shift);

#if (WORD_BYTES == 8)		/* 64-bit words */
static const u8 brainpoolp384r1_p_reciprocal[] = {
	0xD1, 0xB5, 0x75, 0xB1, 0x6D, 0x8E, 0xC6, 0xB8
};
#elif (WORD_BYTES == 4)		/* 32-bit words */
static const u8 brainpoolp384r1_p_reciprocal[] = {
	0xD1, 0xB5, 0x75, 0xB1
};
#elif (WORD_BYTES == 2)		/* 16-bit words */
static const u8 brainpoolp384r1_p_reciprocal[] = {
	0xD1, 0xB5
};
#else /* unknown word size */
#error "Unsupported word size"
#endif
TO_EC_STR_PARAM(brainpoolp384r1_p_reciprocal);

static const u8 brainpoolp384r1_a[] = {
	0x7B, 0xC3, 0x82, 0xC6, 0x3D, 0x8C, 0x15, 0x0C,
	0x3C, 0x72, 0x08, 0x0A, 0xCE, 0x05, 0xAF, 0xA0,
	0xC2, 0xBE, 0xA2, 0x8E, 0x4F, 0xB2, 0x27, 0x87,
	0x13, 0x91, 0x65, 0xEF, 0xBA, 0x91, 0xF9, 0x0F,
	0x8A, 0xA5, 0x81, 0x4A, 0x50, 0x3A, 0xD4, 0xEB,
	0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26
};

TO_EC_STR_PARAM(brainpoolp384r1_a);

static const u8 brainpoolp384r1_b[] = {
	0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26,
	0x8B, 0x39, 0xB5, 0x54, 0x16, 0xF0, 0x44, 0x7C,
	0x2F, 0xB7, 0x7D, 0xE1, 0x07, 0xDC, 0xD2, 0xA6,
	0x2E, 0x88, 0x0E, 0xA5, 0x3E, 0xEB, 0x62, 0xD5,
	0x7C, 0xB4, 0x39, 0x02, 0x95, 0xDB, 0xC9, 0x94,
	0x3A, 0xB7, 0x86, 0x96, 0xFA, 0x50, 0x4C, 0x11
};

TO_EC_STR_PARAM(brainpoolp384r1_b);

static const u8 brainpoolp384r1_npoints[] = {
	0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28,
	0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF,
	0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB3,
	0x1F, 0x16, 0x6E, 0x6C, 0xAC, 0x04, 0x25, 0xA7,
	0xCF, 0x3A, 0xB6, 0xAF, 0x6B, 0x7F, 0xC3, 0x10,
	0x3B, 0x88, 0x32, 0x02, 0xE9, 0x04, 0x65, 0x65
};

TO_EC_STR_PARAM(brainpoolp384r1_npoints);

static const u8 brainpoolp384r1_gx[] = {
	0x1D, 0x1C, 0x64, 0xF0, 0x68, 0xCF, 0x45, 0xFF,
	0xA2, 0xA6, 0x3A, 0x81, 0xB7, 0xC1, 0x3F, 0x6B,
	0x88, 0x47, 0xA3, 0xE7, 0x7E, 0xF1, 0x4F, 0xE3,
	0xDB, 0x7F, 0xCA, 0xFE, 0x0C, 0xBD, 0x10, 0xE8,
	0xE8, 0x26, 0xE0, 0x34, 0x36, 0xD6, 0x46, 0xAA,
	0xEF, 0x87, 0xB2, 0xE2, 0x47, 0xD4, 0xAF, 0x1E
};

TO_EC_STR_PARAM(brainpoolp384r1_gx);

static const u8 brainpoolp384r1_gy[] = {
	0x8A, 0xBE, 0x1D, 0x75, 0x20, 0xF9, 0xC2, 0xA4,
	0x5C, 0xB1, 0xEB, 0x8E, 0x95, 0xCF, 0xD5, 0x52,
	0x62, 0xB7, 0x0B, 0x29, 0xFE, 0xEC, 0x58, 0x64,
	0xE1, 0x9C, 0x05, 0x4F, 0xF9, 0x91, 0x29, 0x28,
	0x0E, 0x46, 0x46, 0x21, 0x77, 0x91, 0x81, 0x11,
	0x42, 0x82, 0x03, 0x41, 0x26, 0x3C, 0x53, 0x15
};

TO_EC_STR_PARAM(brainpoolp384r1_gy);

static const u8 brainpoolp384r1_gz[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

TO_EC_STR_PARAM(brainpoolp384r1_gz);

static const u8 brainpoolp384r1_order[] = {
	0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28,
	0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF,
	0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB3,
	0x1F, 0x16, 0x6E, 0x6C, 0xAC, 0x04, 0x25, 0xA7,
	0xCF, 0x3A, 0xB6, 0xAF, 0x6B, 0x7F, 0xC3, 0x10,
	0x3B, 0x88, 0x32, 0x02, 0xE9, 0x04, 0x65, 0x65
};

TO_EC_STR_PARAM(brainpoolp384r1_order);

#define CURVE_BRAINPOOLP384R1_Q_BITLEN 384
static const u8 brainpoolp384r1_order_bitlen[] = { 0x01, 0x80 };

TO_EC_STR_PARAM(brainpoolp384r1_order_bitlen);

static const u8 brainpoolp384r1_cofactor[] = { 0x01 };

TO_EC_STR_PARAM(brainpoolp384r1_cofactor);

static const u8 brainpoolp384r1_oid[] = "1.3.36.3.3.2.8.1.1.11";
TO_EC_STR_PARAM(brainpoolp384r1_oid);

static const u8 brainpoolp384r1_name[] = "BRAINPOOLP384R1";
TO_EC_STR_PARAM(brainpoolp384r1_name);

static const ec_str_params brainpoolp384r1_str_params = {
#ifdef WIN32
  &brainpoolp384r1_p_str_param,
  &brainpoolp384r1_p_bitlen_str_param,
  &brainpoolp384r1_r_str_param,
  &brainpoolp384r1_r_square_str_param,
  &brainpoolp384r1_mpinv_str_param,
  &brainpoolp384r1_p_shift_str_param,
  &brainpoolp384r1_p_str_param,
  &brainpoolp384r1_p_reciprocal_str_param,
  &brainpoolp384r1_a_str_param,
  &brainpoolp384r1_b_str_param,
  &brainpoolp384r1_npoints_str_param,
  &brainpoolp384r1_gx_str_param,
  &brainpoolp384r1_gy_str_param,
  &brainpoolp384r1_gz_str_param,
  &brainpoolp384r1_order_str_param,
  &brainpoolp384r1_order_bitlen_str_param,
  &brainpoolp384r1_cofactor_str_param,
  &brainpoolp384r1_oid_str_param,
  &brainpoolp384r1_name_str_param,
#else
	.p = &brainpoolp384r1_p_str_param,
	.p_bitlen = &brainpoolp384r1_p_bitlen_str_param,
	.r = &brainpoolp384r1_r_str_param,
	.r_square = &brainpoolp384r1_r_square_str_param,
	.mpinv = &brainpoolp384r1_mpinv_str_param,
	.p_shift = &brainpoolp384r1_p_shift_str_param,
	.p_normalized = &brainpoolp384r1_p_str_param,
	.p_reciprocal = &brainpoolp384r1_p_reciprocal_str_param,
	.a = &brainpoolp384r1_a_str_param,
	.b = &brainpoolp384r1_b_str_param,
	.npoints = &brainpoolp384r1_npoints_str_param,
	.gx = &brainpoolp384r1_gx_str_param,
	.gy = &brainpoolp384r1_gy_str_param,
	.gz = &brainpoolp384r1_gz_str_param,
	.order = &brainpoolp384r1_order_str_param,
	.order_bitlen = &brainpoolp384r1_order_bitlen_str_param,
	.cofactor = &brainpoolp384r1_cofactor_str_param,
	.oid = &brainpoolp384r1_oid_str_param,
	.name = &brainpoolp384r1_name_str_param,
#endif /* WIN32 */
};

/*
 * Compute max bit length of all curves for p and q
 */
#ifndef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN    0
#endif
#if (CURVES_MAX_P_BIT_LEN < CURVE_BRAINPOOLP384R1_P_BITLEN)
#undef CURVES_MAX_P_BIT_LEN
#define CURVES_MAX_P_BIT_LEN CURVE_BRAINPOOLP384R1_P_BITLEN
#endif
#ifndef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN    0
#endif
#if (CURVES_MAX_Q_BIT_LEN < CURVE_BRAINPOOLP384R1_Q_BITLEN)
#undef CURVES_MAX_Q_BIT_LEN
#define CURVES_MAX_Q_BIT_LEN CURVE_BRAINPOOLP384R1_Q_BITLEN
#endif

#endif /* __EC_PARAMS_BRAINPOOLP384R1_H__ */

#endif /* WITH_CURVE_BRAINPOOLP384R1 */
