/* gost-map.c — отображение OpenPGP-идентификаторов ГОСТ → libgcrypt */
#include <config.h>
#include <gcrypt.h>             /* GCRY_CIPHER_…, GCRY_MAC_… */
#include "../common/openpgpdefs.h"  /* CIPHER_ALGO_… , MAC_ALGO_… */
#include "gost-map.h"              /* наши объявления */

/* OpenPGP → libgcrypt: шифрование ГОСТ 28147-89 */
int
map_gost_cipher_openpgp_to_gcry(int openpgp_id)
{
    switch (openpgp_id) {
    case CIPHER_ALGO_GOST28147:
#ifdef GCRY_CIPHER_GOST28147
        return GCRY_CIPHER_GOST28147;
#else
        return GCRY_CIPHER_NONE;
#endif
    default:
        return GCRY_CIPHER_NONE;
    }
}

/* Параметры шифра → строковый OID S-box */
const char *
cipher_params_to_sbox(cipher_params_t params)
{
    switch (params) {
    case CIPHER_PARAMS_GOST28147_A: return "1.2.643.2.2.31.1";
    case CIPHER_PARAMS_GOST28147_B: return "1.2.643.2.2.31.2";
    case CIPHER_PARAMS_GOST28147_C: return "1.2.643.2.2.31.3";
    case CIPHER_PARAMS_GOST28147_D: return "1.2.643.2.2.31.4";
    case CIPHER_PARAMS_GOST28147_Z: return "1.2.643.7.1.2.5.1.1";
    default:                        return NULL;
    }
}

/* OpenPGP → libgcrypt: MAC ГОСТ 28147-89 */
int
map_mac_openpgp_to_gcry(int openpgp_id)
{
    switch (openpgp_id) {
    case MAC_ALGO_GOST28147_IMIT:
#ifdef GCRY_MAC_GOST28147_IMIT
        return GCRY_MAC_GOST28147_IMIT;
#else
        return GCRY_MAC_NONE;
#endif
    default:
        return GCRY_MAC_NONE;
    }
}

/* Параметры MAC → строковый OID S-box */
const char *
mac_params_to_sbox(mac_params_t params)
{
    switch (params) {
    case MAC_PARAMS_GOST28147_A: return "1.2.643.2.2.31.1";
    case MAC_PARAMS_GOST28147_B: return "1.2.643.2.2.31.2";
    case MAC_PARAMS_GOST28147_C: return "1.2.643.2.2.31.3";
    case MAC_PARAMS_GOST28147_D: return "1.2.643.2.2.31.4";
    case MAC_PARAMS_GOST28147_Z: return "1.2.643.7.1.2.5.1.1";
    default:                     return NULL;
    }
}
