#ifndef GNUPG_G10_GOST_MAP_H
#define GNUPG_G10_GOST_MAP_H

#include <gcrypt.h>             /* for GCRY_CIPHER_*, GCRY_MAC_* */
#include "../common/openpgpdefs.h"  /* for CIPHER_ALGO_*, MAC_ALGO_*, cipher_params_t, mac_params_t */

/* Map OpenPGP cipher ID to libgcrypt cipher algorithm */
int map_gost_cipher_openpgp_to_gcry(int openpgp_id);

/* Return the OID string for a given GOST28147-89 cipher parameter */
const char *cipher_params_to_sbox(cipher_params_t params);

/* Map OpenPGP MAC ID to libgcrypt MAC algorithm */
int map_mac_openpgp_to_gcry(int openpgp_id);

/* Return the OID string for a given GOST28147-89 MAC parameter */
const char *mac_params_to_sbox(mac_params_t params);

#endif /* GNUPG_G10_GOST_MAP_H */
