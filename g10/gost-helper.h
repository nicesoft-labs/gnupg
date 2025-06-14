#ifndef GNUPG_G10_GOST_HELPER_H
#define GNUPG_G10_GOST_HELPER_H

#include <gpg-error.h>
#include <gcrypt.h>
#include "gost-kdf.h"

/* Извлечь из публичного ключа массив MPI параметры KDF/VKO */
gpg_error_t pk_gost_get_kdf_params(gcry_mpi_t *pkey,
                                   gost_kdf_params_t **r_params);

#endif /* GNUPG_G10_GOST_HELPER_H */
