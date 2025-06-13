#ifndef GNUPG_G10_GOST_KDF_H
#define GNUPG_G10_GOST_KDF_H

#include "../common/openpgpdefs.h"
#include <gcrypt.h>
#include <gpg-error.h>

#define GOST_KDF_PARAMS_VERSION 2

/* Parameter descriptors.  */
typedef enum
  {
    DIGEST_PARAMS_UNSPECIFIED = 0,
    DIGEST_PARAMS_GOSTR3411_94_A = 1
  } digest_params_t;

typedef enum
  {
    CIPHER_PARAMS_GOST28147_A = 1,
    CIPHER_PARAMS_GOST28147_B = 2,
    CIPHER_PARAMS_GOST28147_C = 3,
    CIPHER_PARAMS_GOST28147_D = 4,
    CIPHER_PARAMS_GOST28147_Z = 5
  } cipher_params_t;

typedef enum
  {
    MAC_PARAMS_UNSPECIFIED = 0,
    MAC_PARAMS_GOST28147_A = 1,
    MAC_PARAMS_GOST28147_B = 2,
    MAC_PARAMS_GOST28147_C = 3,
    MAC_PARAMS_GOST28147_D = 4,
    MAC_PARAMS_GOST28147_Z = 5
  } mac_params_t;

typedef enum { VKO_7836 = 1 } vko_algo_t;

typedef enum { KDF_NULL = 0, GOST_KDF_CPDIVERS = 1, GOST_KDF_TREE = 2 } kdf_algo_t;

typedef enum { KEYWRAP_7836 = 1 } keywrap_algo_t;

typedef struct
{
  vko_algo_t vko_algo;
  union
  {
    struct
    {
      unsigned char ukm_len;
      digest_algo_t   vko_digest_algo;
      digest_params_t vko_digest_params;
    } vko_7836;
  } vko_params;
  kdf_algo_t kdf_algo;
  union
  {
    struct
    {
      cipher_algo_t kdf_cipher_algo;
      cipher_params_t kdf_cipher_params;
    } kdf_4357;
    struct
    {
      unsigned char seed_len;
      char *label;
      unsigned char R;
      unsigned int L;
      digest_algo_t   kdf_digest_algo;
      digest_params_t kdf_digest_params;
    } kdf_7836;
  } kdf_params;
  keywrap_algo_t keywrap_algo;
  union
  {
    struct
    {
      mac_algo_t   keywrap_mac_algo;
      mac_params_t keywrap_mac_params;
      cipher_algo_t   keywrap_cipher_algo;
      cipher_params_t keywrap_cipher_params;
    } keywrap_7836;
  } keywrap_params;
} gost_kdf_params_t;

/* Function prototypes.  */
gpg_error_t gost_vko_kdf (const gost_kdf_params_t *params, gcry_mpi_t shared,
                          gcry_mpi_t ukm, gcry_mpi_t *out_kek);

gpg_error_t gost_kdf (const gost_kdf_params_t *params, gcry_mpi_t ukm,
                       const unsigned char *shared_buf, size_t shared_len,
                       gcry_mpi_t *out_kek);

void free_gost_kdf_params (gost_kdf_params_t *params);

#endif /* GNUPG_G10_GOST_KDF_H */
