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
#include "hash_algs.h"

const hash_mapping hash_maps[] = {
#ifdef WITH_HASH_SHA224
 {
#ifdef WIN32
 SHA224,
#ifndef NO_NAMES
 "SHA224",
#endif
 SHA224_DIGEST_SIZE,
 SHA224_BLOCK_SIZE,
 (_hfunc_init) sha224_init,
 (_hfunc_update) sha224_update,
 (_hfunc_finalize) sha224_final,
 sha224_scattered
#else
	.type = SHA224,	/* SHA224 */
	 .name = "SHA224",
	 .digest_size = SHA224_DIGEST_SIZE,
	 .block_size = SHA224_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha224_init,
	 .hfunc_update = (_hfunc_update) sha224_update,
	 .hfunc_finalize = (_hfunc_finalize) sha224_final,
	 .hfunc_scattered = sha224_scattered
#endif /* WIN32 */
},
#endif /* WITH_HASH_SHA224 */
#ifdef WITH_HASH_SHA256
 {
#ifdef WIN32
 SHA256,	/* SHA256 */
#ifndef NO_NAMES
 "SHA256",
#endif
 SHA256_DIGEST_SIZE,
 SHA256_BLOCK_SIZE,
 (_hfunc_init) sha256_init,
 (_hfunc_update) sha256_update,
 (_hfunc_finalize) sha256_final,
 sha256_scattered
#else
	 .type = SHA256,	/* SHA256 */
	 .name = "SHA256",
	 .digest_size = SHA256_DIGEST_SIZE,
	 .block_size = SHA256_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha256_init,
	 .hfunc_update = (_hfunc_update) sha256_update,
	 .hfunc_finalize = (_hfunc_finalize) sha256_final,
	 .hfunc_scattered = sha256_scattered
#endif /* WIN32 */
},
#endif /* WITH_HASH_SHA256 */
#ifdef WITH_HASH_SHA384
 {
#ifdef WIN32
 SHA384,	/* SHA384 */
#ifndef NO_NAMES
 "SHA384",
#endif
 SHA384_DIGEST_SIZE,
 SHA384_BLOCK_SIZE,
 (_hfunc_init) sha384_init,
 (_hfunc_update) sha384_update,
 (_hfunc_finalize) sha384_final,
 sha384_scattered
#else
	 .type = SHA384,	/* SHA384 */
	 .name = "SHA384",
	 .digest_size = SHA384_DIGEST_SIZE,
	 .block_size = SHA384_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha384_init,
	 .hfunc_update = (_hfunc_update) sha384_update,
	 .hfunc_finalize = (_hfunc_finalize) sha384_final,
	 .hfunc_scattered = sha384_scattered
#endif /* WIN32 */
},
#endif /* WITH_HASH_SHA384 */
#ifdef WITH_HASH_SHA512
 {
#ifdef WIN32
 SHA512,	/* SHA512 */
#ifndef NO_NAMES
 "SHA512"
#endif
 SHA512_DIGEST_SIZE,
 SHA512_BLOCK_SIZE,
 (_hfunc_init) sha512_init,
 (_hfunc_update) sha512_update,
 (_hfunc_finalize) sha512_final,
 sha512_scattered
#else
	 .type = SHA512,	/* SHA512 */
	 .name = "SHA512",
	 .digest_size = SHA512_DIGEST_SIZE,
	 .block_size = SHA512_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha512_init,
	 .hfunc_update = (_hfunc_update) sha512_update,
	 .hfunc_finalize = (_hfunc_finalize) sha512_final,
	 .hfunc_scattered = sha512_scattered
#endif /* WIN32 */
},
#endif /* WITH_HASH_SHA512 */
#ifdef WITH_HASH_SHA512_224
 {
#ifdef WIN32
 SHA512_224,	/* SHA512_224 */
#ifndef NO_NAMES
 "SHA512_224",
#endif
 SHA512_224_DIGEST_SIZE,
 SHA512_224_BLOCK_SIZE,
 (_hfunc_init) sha512_224_init,
 (_hfunc_update) sha512_224_update,
 (_hfunc_finalize) sha512_224_final,
 sha512_224_scattered
#else
	 .type = SHA512_224,	/* SHA512_224 */
	 .name = "SHA512_224",
	 .digest_size = SHA512_224_DIGEST_SIZE,
	 .block_size = SHA512_224_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha512_224_init,
	 .hfunc_update = (_hfunc_update) sha512_224_update,
	 .hfunc_finalize = (_hfunc_finalize) sha512_224_final,
	 .hfunc_scattered = sha512_224_scattered
#endif /* WIN32 */
},
#if (MAX_HASH_ALG_NAME_LEN < 7)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 7
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA512_224 */
#ifdef WITH_HASH_SHA512_256
 {
#ifdef WIN32
 SHA512_256,	/* SHA512_256 */
#ifndef NO_NAMES
 "SHA512_256",
#endif
 SHA512_256_DIGEST_SIZE,
 SHA512_256_BLOCK_SIZE,
 (_hfunc_init) sha512_256_init,
 (_hfunc_update) sha512_256_update,
 (_hfunc_finalize) sha512_256_final,
 sha512_256_scattered
#else
 	 .type = SHA512_256,	/* SHA512_256 */
	 .name = "SHA512_256",
	 .digest_size = SHA512_256_DIGEST_SIZE,
	 .block_size = SHA512_256_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha512_256_init,
	 .hfunc_update = (_hfunc_update) sha512_256_update,
	 .hfunc_finalize = (_hfunc_finalize) sha512_256_final,
	 .hfunc_scattered = sha512_256_scattered
#endif /* WIN32 */
},
#endif /* WITH_HASH_SHA512_256 */
#ifdef WITH_HASH_SHA3_224
 {
#ifdef WIN32
 SHA3_224,	/* SHA3_224 */
#ifndef NO_NAMES
 "SHA3_224",
#endif
 SHA3_224_DIGEST_SIZE,
 SHA3_224_BLOCK_SIZE,
 (_hfunc_init) sha3_224_init,
 (_hfunc_update) sha3_224_update,
 (_hfunc_finalize) sha3_224_final,
 sha3_224_scattered
#else
	.type = SHA3_224,	/* SHA3_224 */
	 .name = "SHA3_224",
	 .digest_size = SHA3_224_DIGEST_SIZE,
	 .block_size = SHA3_224_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha3_224_init,
	 .hfunc_update = (_hfunc_update) sha3_224_update,
	 .hfunc_finalize = (_hfunc_finalize) sha3_224_final,
	 .hfunc_scattered = sha3_224_scattered
#endif /* WIN32 */
},
#if (MAX_HASH_ALG_NAME_LEN < 9)
#undef MAX_HASH_ALG_NAME_LEN
#define MAX_HASH_ALG_NAME_LEN 9
#endif /* MAX_HASH_ALG_NAME_LEN */
#endif /* WITH_HASH_SHA3_224 */
#ifdef WITH_HASH_SHA3_256
 {
#ifdef WIN32
 SHA3_256,	/* SHA3_256 */
#ifndef NO_NAMES
 "SHA3_256",
#endif
 SHA3_256_DIGEST_SIZE,
 SHA3_256_BLOCK_SIZE,
 (_hfunc_init) sha3_256_init,
 (_hfunc_update) sha3_256_update,
 (_hfunc_finalize) sha3_256_final,
 sha3_256_scattered
#else
	 .type = SHA3_256,	/* SHA3_256 */
	 .name = "SHA3_256",
	 .digest_size = SHA3_256_DIGEST_SIZE,
	 .block_size = SHA3_256_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha3_256_init,
	 .hfunc_update = (_hfunc_update) sha3_256_update,
	 .hfunc_finalize = (_hfunc_finalize) sha3_256_final,
	 .hfunc_scattered = sha3_256_scattered
#endif /* WIN32 */
},
#endif /* WITH_HASH_SHA3_256 */
#ifdef WITH_HASH_SHA3_384
{
#ifdef WIN32
 SHA3_384,	/* SHA3_384 */
#ifndef NO_NAMES
 "SHA3_384",
#endif
 SHA3_384_DIGEST_SIZE,
 SHA3_384_BLOCK_SIZE,
 (_hfunc_init) sha3_384_init,
 (_hfunc_update) sha3_384_update,
 (_hfunc_finalize) sha3_384_final,
 sha3_384_scattered
#else
         .type = SHA3_384,	/* SHA3_384 */
	 .name = "SHA3_384",
	 .digest_size = SHA3_384_DIGEST_SIZE,
	 .block_size = SHA3_384_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha3_384_init,
	 .hfunc_update = (_hfunc_update) sha3_384_update,
	 .hfunc_finalize = (_hfunc_finalize) sha3_384_final,
	 .hfunc_scattered = sha3_384_scattered
#endif /* WIN32 */
},
#endif /* WITH_HASH_SHA3_384 */
#ifdef WITH_HASH_SHA3_512
{
#ifdef WIN32
 SHA3_512,	/* SHA3_512 */
#ifndef NO_NAMES
 "SHA3_512",
#endif
 SHA3_512_DIGEST_SIZE,
 SHA3_512_BLOCK_SIZE,
 (_hfunc_init) sha3_512_init,
 (_hfunc_update) sha3_512_update,
 (_hfunc_finalize) sha3_512_final,
 sha3_512_scattered
#else
	 .type = SHA3_512,	/* SHA3_512 */
	 .name = "SHA3_512",
	 .digest_size = SHA3_512_DIGEST_SIZE,
	 .block_size = SHA3_512_BLOCK_SIZE,
	 .hfunc_init = (_hfunc_init) sha3_512_init,
	 .hfunc_update = (_hfunc_update) sha3_512_update,
	 .hfunc_finalize = (_hfunc_finalize) sha3_512_final,
	 .hfunc_scattered = sha3_512_scattered
#endif /* WIN32 */
},
#endif /* WITH_HASH_SHA3_512 */
{
#ifdef WIN32
 UNKNOWN_HASH_ALG,	/* Needs to be kept last */
#ifndef NO_NAMES
 "UNKNOWN",
#endif
 0,
 0,
 NULL,
 NULL,
 NULL,
 NULL,
#else
	 .type = UNKNOWN_HASH_ALG,	/* Needs to be kept last */
	 .name = "UNKNOWN",
	 .digest_size = 0,
	 .block_size = 0,
	 .hfunc_init = NULL,
	 .hfunc_update = NULL,
	 .hfunc_finalize = NULL,
	 .hfunc_scattered = NULL
#endif /* WIN32 */
},
};

#ifndef NO_NAMES
const hash_mapping *get_hash_by_name(const char *hash_name)
{
	const hash_mapping *m = NULL, *ret = NULL;
	u8 i;

	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
		const char *exp_name = (const char *)m->name;

		if (are_str_equal(hash_name, exp_name)) {
			ret = m;
			break;
		}
	}

	return ret;
}
#endif /* !NO_NAMES */

const hash_mapping *get_hash_by_type(hash_alg_type hash_type)
{
	const hash_mapping *m = NULL, *ret = NULL;
	u8 i;

	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
		if (m->type == hash_type) {
			ret = m;
			break;
		}
	}

	return ret;
}

/*
 * Returns respectively in digest_size and block_size param the digest size
 * and block size for given hash function, if return value of the function is 0.
 * If return value is -1, then the hash algorithm is not known and output
 * parameters are not modified.
 */
int get_hash_sizes(hash_alg_type hash_type, u8 *digest_size, u8 *block_size)
{
	const hash_mapping *m;
	int ret = -1;
	u8 i;

	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
		if (m->type == hash_type) {
			if (digest_size != NULL) {
				*digest_size = m->digest_size;
			}
			if (block_size != NULL) {
				*block_size = m->block_size;
			}
			ret = 0;
			break;
		}
	}

	return ret;
}

/* Here, we provide a helper that sanity checks the provided hash
 * mapping against our constant ones.
 */
int hash_mapping_callbacks_sanity_check(const hash_mapping *h)
{
	const hash_mapping *m;
        u8 i;

        if(h == NULL){
                goto err;
        }
        /* We just check is our mapping is indeed
         * one of the registered mappings.
         */
	for (i = 0, m = &hash_maps[i]; m->type != UNKNOWN_HASH_ALG;
	     m = &hash_maps[++i]) {
                if(m->type == h->type){
#ifndef NO_NAMES
			if(!are_str_equal_nlen(m->name, h->name, MAX_HASH_ALG_NAME_LEN)){
				goto err;
			} else
#endif /* !NO_NAMES */
			if(m->digest_size != h->digest_size){
				goto err;
			}
			else if(m->block_size != h->block_size){
				goto err;
			}
			else if(m->hfunc_init != h->hfunc_init){
				goto err;
			}
			else if(m->hfunc_update != h->hfunc_update){
				goto err;
			}
			else if(m->hfunc_finalize != h->hfunc_finalize){
				goto err;
			}
			else if(m->hfunc_scattered != h->hfunc_scattered){
				goto err;
			}
                        else{
                                return 0;
                        }
                }
        }

err:
        return -1;
}

