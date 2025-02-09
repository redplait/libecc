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
#ifndef __EC_PARAMS_H__
#define __EC_PARAMS_H__
#include "../fp/fp.h"
#include "prj_pt.h"
#include "known/ec_params_external.h"

/* Info: this include is here because an update on
 * MAX_CURVE_OID_LEN and MAX_CURVE_NAME_LEN can be done
 * through preprocessing of the curves at compile time.
 */
#include "curves_list.h"
/* These default sizes should be enough for the known curves */
#ifdef MAX_CURVE_NAME_LEN
#if (MAX_CURVE_OID_LEN < 32)
#undef MAX_CURVE_OID_LEN
#define MAX_CURVE_OID_LEN  32	/* including trailing 0 */
#endif
#else
#define MAX_CURVE_OID_LEN  32	/* including trailing 0 */
#endif

#ifdef MAX_CURVE_NAME_LEN
#if (MAX_CURVE_NAME_LEN < 32)
#undef MAX_CURVE_NAME_LEN
#define MAX_CURVE_NAME_LEN 32	/* including trailing 0 */
#endif
#else
#define MAX_CURVE_NAME_LEN 32
#endif

/*
 * Elliptic curves parameters. We only support
 * curves defined on prime fields (i.e. Fp,
 * with p prime).
 */
typedef struct {
	/* Fp */
	fp_ctx ec_fp;

	/* Curve */
	ec_shortw_crv ec_curve;

	/* Number of points on curve */
	nn ec_curve_points;

	/*
	 * Generator G defining our group, in projective
	 * coordinates.
	 */
	prj_pt ec_gen;

	/* Number of points on group generated by G */
	nn ec_gen_order;
	bitcnt_t ec_gen_order_bitlen;

	/* Curve cofactor */
	nn ec_gen_cofactor;

#ifndef NO_OIDS
	/* Object Identifier for the curve */
	u8 curve_oid[MAX_CURVE_OID_LEN];
#endif /* NO_OIDS */

#ifndef NO_NAMES
	/* Short name for the curve */
	u8 curve_name[MAX_CURVE_NAME_LEN];
#endif /* !NO_NAMES */
} ec_params;

void import_params(ec_params *out_params, const ec_str_params *in_str_params);

#endif /* __EC_PARAMS_H__ */
