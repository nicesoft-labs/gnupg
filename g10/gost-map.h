#ifndef GNUPG_G10_GOST_MAP_H
#define GNUPG_G10_GOST_MAP_H

#include "gost-kdf.h"
#include "../common/openpgpdefs.h"
#include <gcrypt.h>

int map_gost_cipher_openpgp_to_gcry (int openpgp_id);
const char *cipher_params_to_sbox (cipher_params_t *params);
int map_mac_openpgp_to_gcry (int openpgp_id);
const char *mac_params_to_sbox (mac_params_t *params);

#endif /* GNUPG_G10_GOST_MAP_H */
