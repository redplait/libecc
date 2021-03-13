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
#ifndef __HASH_ALGS_H__
#define __HASH_ALGS_H__

#include "../lib_ecc_config.h"
#include "../lib_ecc_types.h"
#include "../words/words.h"
#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
#include "sha512-224.h"
#include "sha512-256.h"
#include "sha3-224.h"
#include "sha3-256.h"
#include "sha3-384.h"
#include "sha3-512.h"
#include "../utils/utils.h"

#if (MAX_DIGEST_SIZE == 0)
#error "It seems you disabled all hash algorithmsin lib_ecc_config.h"
#endif

#if (MAX_BLOCK_SIZE == 0)
#error "It seems you disabled all hash algorithmsin lib_ecc_config.h"
#endif

typedef union {
#ifdef SHA224_BLOCK_SIZE
	sha224_context sha224;
#endif
#ifdef SHA256_BLOCK_SIZE
	sha256_context sha256;
#endif
#ifdef SHA384_BLOCK_SIZE
	sha384_context sha384;
#endif
#ifdef SHA512_BLOCK_SIZE
	sha512_context sha512;
#endif
#ifdef SHA512_224_BLOCK_SIZE
	sha512_224_context sha512_224;
#endif
#ifdef SHA512_256_BLOCK_SIZE
	sha512_256_context sha512_256;
#endif
#ifdef SHA3_224_BLOCK_SIZE
	sha3_224_context sha3_224;
#endif
#ifdef SHA3_256_BLOCK_SIZE
	sha3_256_context sha3_256;
#endif
#ifdef SHA3_384_BLOCK_SIZE
	sha3_384_context sha3_384;
#endif
#ifdef SHA3_512_BLOCK_SIZE
	sha3_512_context sha3_512;
#endif
} hash_context;

typedef void (*_hfunc_init) (hash_context * hctx);
typedef void (*_hfunc_update) (hash_context * hctx,
			       const unsigned char *chunk, u32 chunklen);
typedef void (*_hfunc_finalize) (hash_context * hctx, unsigned char *output);
typedef void (*_hfunc_scattered) (const unsigned char **inputs,
				  const u32 *ilens, unsigned char *output);

#ifndef NO_NAMES
#define HASH_MAPPING_SANITY_CHECK(A)			\
	MUST_HAVE(((A) != NULL) && 			\
		  ((A)->name != NULL) &&		\
		  ((A)->hfunc_init != NULL) &&		\
		  ((A)->hfunc_update != NULL) &&	\
		  ((A)->hfunc_finalize != NULL) &&	\
		  ((A)->hfunc_scattered != NULL))
#else
#define HASH_MAPPING_SANITY_CHECK(A)			\
	MUST_HAVE(((A) != NULL) && 			\
		  ((A)->hfunc_init != NULL) &&		\
		  ((A)->hfunc_update != NULL) &&	\
		  ((A)->hfunc_finalize != NULL) &&	\
		  ((A)->hfunc_scattered != NULL))
#endif /* NO_NAMES */

/*
 * All the hash algorithms we support are abstracted using the following
 * structure (and following map) which provides for each hash alg its
 * digest size, its block size and the associated scattered function.
 */
typedef struct {
	hash_alg_type type;
#ifndef NO_NAMES
	const char *const name;
#endif /* NO_NAMES */
	u8 digest_size;
	u8 block_size;
	_hfunc_init hfunc_init;
	_hfunc_update hfunc_update;
	_hfunc_finalize hfunc_finalize;
	_hfunc_scattered hfunc_scattered;
} hash_mapping;

extern const hash_mapping hash_maps[];

#define MAX_HASH_ALG_NAME_LEN	0
#ifdef WITH_HASH_SHA224

#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA224 */

#ifdef WITH_HASH_SHA256

#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA256 */

#ifdef WITH_HASH_SHA384

#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA384 */

#ifdef WITH_HASH_SHA512

#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA512 */

#ifdef WITH_HASH_SHA512_224

#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA512_224 */

#ifdef WITH_HASH_SHA512_256

#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA512_256 */

#ifdef WITH_HASH_SHA3_224

#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA3_224 */

#ifdef WITH_HASH_SHA3_256

#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA3_256 */

#ifdef WITH_HASH_SHA3_384

#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA3_384 */

#ifdef WITH_HASH_SHA3_512

#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */

#endif /* WITH_HASH_SHA3_512 */

#ifndef NO_NAMES
const hash_mapping *get_hash_by_name(const char *hash_name);
#endif /* !NO_NAMES */
const hash_mapping *get_hash_by_type(hash_alg_type hash_type);
int get_hash_sizes(hash_alg_type hash_type, u8 *digest_size, u8 *block_size);
int hash_mapping_callbacks_sanity_check(const hash_mapping *h);

#endif /* __HASH_ALGS_H__ */
