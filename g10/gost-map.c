#include <config.h>
#include "gost-map.h"

int
map_gost_cipher_openpgp_to_gcry (int openpgp_id)
{
  switch (openpgp_id)
    {
    case CIPHER_ALGO_GOST28147:
#ifdef GCRY_CIPHER_GOST28147
      return GCRY_CIPHER_GOST28147;
#else
      return 0;
#endif
    default:
      return 0;
    }
}

const char *
cipher_params_to_sbox (cipher_params_t *cipher_params)
{
  switch ((int)(intptr_t)*cipher_params)
    {
    case CIPHER_PARAMS_GOST28147_A: return "1.2.643.2.2.31.1";
    case CIPHER_PARAMS_GOST28147_B: return "1.2.643.2.2.31.2";
    case CIPHER_PARAMS_GOST28147_C: return "1.2.643.2.2.31.3";
    case CIPHER_PARAMS_GOST28147_D: return "1.2.643.2.2.31.4";
    case CIPHER_PARAMS_GOST28147_Z: return "1.2.643.7.1.2.5.1.1";
    default: return NULL;
    }
}

int
map_mac_openpgp_to_gcry (int openpgp_id)
{
  switch (openpgp_id)
    {
    case MAC_ALGO_GOST28147_IMIT:
#ifdef GCRY_MAC_GOST28147_IMIT
      return GCRY_MAC_GOST28147_IMIT;
#else
      return 0;
#endif
    default:
      return 0;
    }
}

const char *
mac_params_to_sbox (mac_params_t *mac_params)
{
  switch ((int)(intptr_t)*mac_params)
    {
    case MAC_PARAMS_GOST28147_A: return "1.2.643.2.2.31.1";
    case MAC_PARAMS_GOST28147_B: return "1.2.643.2.2.31.2";
    case MAC_PARAMS_GOST28147_C: return "1.2.643.2.2.31.3";
    case MAC_PARAMS_GOST28147_D: return "1.2.643.2.2.31.4";
    case MAC_PARAMS_GOST28147_Z: return "1.2.643.7.1.2.5.1.1";
    default: return NULL;
    }
}

