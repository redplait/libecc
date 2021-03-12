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
#ifndef __CURVES_LIST_H__
#define __CURVES_LIST_H__

#include "../lib_ecc_config.h"
#include "../lib_ecc_types.h"
#include "../words/words.h"
#include "known/ec_params_brainpoolp224r1.h"
#include "known/ec_params_brainpoolp256r1.h"
#include "known/ec_params_brainpoolp384r1.h"
#include "known/ec_params_brainpoolp512r1.h"
#include "known/ec_params_secp192r1.h"
#include "known/ec_params_secp224r1.h"
#include "known/ec_params_secp256r1.h"
#include "known/ec_params_secp384r1.h"
#include "known/ec_params_secp521r1.h"
#include "known/ec_params_frp256v1.h"
#include "known/ec_params_gost256.h"
#include "known/ec_params_gost512.h"

/* ADD curves header here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */

#ifndef CURVES_MAX_P_BIT_LEN
#error "Max p bit length is 0; did you disable all curves in lib_ecc_config.h?"
#endif
#if (CURVES_MAX_Q_BIT_LEN > 65535)
#error "Prime field length (in bytes) MUST fit on an u16!"
#endif

#ifndef CURVES_MAX_Q_BIT_LEN
#error "Max q bit length is 0; did you disable all curves in lib_ecc_config.h?"
#endif
#if (CURVES_MAX_Q_BIT_LEN > 65535)
#error "Curve order length (in bytes) MUST fit on an u16!"
#endif

typedef struct {
	ec_curve_type type;
	const ec_str_params *params;
} ec_mapping;

static const ec_mapping ec_maps[] = {
#ifdef WITH_CURVE_FRP256V1
	{FRP256V1, &frp256v1_str_params},
#endif /* WITH_CURVE_FRP256V1 */
#ifdef WITH_CURVE_SECP192R1
	{ SECP192R1, &secp192r1_str_params},
#endif /* WITH_CURVE_SECP192R1 */
#ifdef WITH_CURVE_SECP224R1
	{ SECP224R1, &secp224r1_str_params},
#endif /* WITH_CURVE_SECP224R1 */
#ifdef WITH_CURVE_SECP256R1
	{ SECP256R1, &secp256r1_str_params},
#endif /* WITH_CURVE_SECP256R1 */
#ifdef WITH_CURVE_SECP384R1
	{ SECP384R1, &secp384r1_str_params},
#endif /* WITH_CURVE_SECP384R1 */
#ifdef WITH_CURVE_SECP521R1
	{ SECP521R1, &secp521r1_str_params},
#endif /* WITH_CURVE_SECP521R1 */
#ifdef WITH_CURVE_BRAINPOOLP224R1
	{ BRAINPOOLP224R1, &brainpoolp224r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP224R1 */
#ifdef WITH_CURVE_BRAINPOOLP256R1
	{ BRAINPOOLP256R1, &brainpoolp256r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP256R1 */
#ifdef WITH_CURVE_BRAINPOOLP384R1
	{ BRAINPOOLP384R1, &brainpoolp384r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP384R1 */
#ifdef WITH_CURVE_BRAINPOOLP512R1
	{ BRAINPOOLP512R1, &brainpoolp512r1_str_params},
#endif /* WITH_CURVE_BRAINPOOLP512R1 */
#ifdef WITH_CURVE_GOST256
	{ GOST256, &GOST_256bits_curve_str_params},
#endif /* WITH_CURVE_GOST256 */
#ifdef WITH_CURVE_GOST512
	{ GOST512, &GOST_512bits_curve_str_params},
#endif /* WITH_CURVE_GOST512 */
/* ADD curves mapping here */
/* XXX: Do not remove the comment above, as it is
 * used by external tools as a placeholder to add or
 * remove automatically generated code.
 */
};

/*
 * Number of cuvres supported by the lib, i.e. number of elements in
 * ec_maps array above.
 */
#define EC_CURVES_NUM (sizeof(ec_maps) / sizeof(ec_mapping))
#endif /* __CURVES_LIST_H__ */
