#pragma once

#include "dict.h"
#include "libsig.h"
#include "allocstat.h"

typedef struct _ECDSA_DEVICE_EXTENSION
{
  ERESOURCE DataResource;
  dict_t *proc_dict;
  /* ecdsa allocations stat */
  struct alloc_stat ecdsa_astat;
  /* ecdsa data */
  const ec_sig_mapping *g_sm;
  const ec_str_params *g_ec_str_p;
  hash_alg_type g_hash_type;
  ec_params params;
  ec_pub_key g_pub_key;
  u8 g_siglen;
} ECDSA_DEVICE_EXTENSION, *PECDSA_DEVICE_EXTENSION;
