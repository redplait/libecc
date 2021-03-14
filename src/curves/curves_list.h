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

#define SKIP_DATA
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
#undef SKIP_DATA

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

extern const ec_mapping ec_maps[];

size_t get_ec_maps_size();

#endif /* __CURVES_LIST_H__ */
