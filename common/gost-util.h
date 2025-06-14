#ifndef GNUPG_COMMON_GOST_UTIL_H
#define GNUPG_COMMON_GOST_UTIL_H

#include <gcrypt.h>       /* We need this for the memory function protos. */
#include <errno.h>        /* We need errno.  */
#include <gpg-error.h>    /* We need gpg_error_t and estream. */
#include "openpgpdefs.h"  /* We need gpg_error_t and estream. */

/* <-- Вот эта строка нужна, чтобы решить твою ошибку линковки */
void flip_buffer(unsigned char *buffer, unsigned int length);

gpg_error_t
gost_generate_ukm (unsigned int ukm_blen, gcry_mpi_t *r_ukm);

gpg_error_t
gost_cpdiversify_key (gcry_mpi_t *result,
                      enum gcry_cipher_algos cipher_algo,
                      const char *cipher_sbox,
                      const unsigned char *key, size_t key_len,
                      gcry_mpi_t ukm);

gpg_error_t
gost_keywrap (gcry_mpi_t *result,
              enum gcry_cipher_algos cipher_algo,
              const char *cipher_sbox,
              enum gcry_mac_algos mac_algo,
              const char *mac_sbox,
              gcry_mpi_t key, gcry_mpi_t ukm, gcry_mpi_t kek);

gpg_error_t
gost_vko (gcry_mpi_t shared, enum gcry_md_algos digest_algo,
          const char *digest_params, unsigned char **keyout,
          size_t *keyout_len);

gpg_error_t
gost_keyunwrap (gcry_mpi_t *result,
                enum gcry_cipher_algos cipher_algo,
                const char *cipher_sbox,
                enum gcry_mac_algos mac_algo,
                const char *mac_sbox,
                const unsigned char *wrapped, size_t wrapped_len,
                gcry_mpi_t ukm, gcry_mpi_t kek);

#endif /*GNUPG_COMMON_GOST_UTIL_H*/
