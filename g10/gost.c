/* gost.c - GOST public key operations for GnuPG
 * This is a trimmed version adapted for GnuPG 2.5.8.
 * Copyright (C) 2019 Paul Wolneykien
 *
 * This file is part of GnuPG.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gpg.h"
#include "../common/util.h"
#include "../common/gost-util.h"
#include "pkglue.h"
#include "main.h"

/* Version marker used with packed GOST parameter sets.  */
#define GOST_KDF_PARAMS_VERSION 2

/* -- Parameter descriptors --  */
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

typedef enum { KDF_NULL = 0, GOST_KDF_CPDIVERS = 1 } kdf_algo_t;

typedef enum { KEYWRAP_7836 = 1 } keywrap_algo_t;

typedef struct
{
  vko_algo_t vko_algo;
  struct
  {
    unsigned char ukm_len;
    digest_algo_t vko_digest_algo;
    digest_params_t vko_digest_params;
  } vko_7836;
  kdf_algo_t kdf_algo;
  struct
  {
    cipher_algo_t kdf_cipher_algo;
    cipher_params_t kdf_cipher_params;
  } kdf_4357;
  keywrap_algo_t keywrap_algo;
  struct
  {
    mac_algo_t keywrap_mac_algo;
    mac_params_t keywrap_mac_params;
    cipher_algo_t keywrap_cipher_algo;
    cipher_params_t keywrap_cipher_params;
  } keywrap_7836;
} gost_kdf_params_t;

/* Default parameter table for supported curves.  */
static const struct
{
  const char *oidpfx;
  unsigned int qbits;
  gost_kdf_params_t params;
} gost_kdf_params_table[] =
  {
    { "1.2.643.7.1.2.1.1.", 256,
      { VKO_7836, { 8, DIGEST_ALGO_GOSTR3411_12_256, DIGEST_PARAMS_UNSPECIFIED },
        GOST_KDF_CPDIVERS, { CIPHER_ALGO_GOST28147, CIPHER_PARAMS_GOST28147_Z },
        KEYWRAP_7836,
        { MAC_ALGO_GOST28147_IMIT, MAC_PARAMS_GOST28147_Z,
          CIPHER_ALGO_GOST28147, CIPHER_PARAMS_GOST28147_Z } }
    },
    { "1.2.643.7.1.2.1.2.", 512,
      { VKO_7836, { 8, DIGEST_ALGO_GOSTR3411_12_256, DIGEST_PARAMS_UNSPECIFIED },
        GOST_KDF_CPDIVERS, { CIPHER_ALGO_GOST28147, CIPHER_PARAMS_GOST28147_Z },
        KEYWRAP_7836,
        { MAC_ALGO_GOST28147_IMIT, MAC_PARAMS_GOST28147_Z,
          CIPHER_ALGO_GOST28147, CIPHER_PARAMS_GOST28147_Z } }
    }
  };

/* Pack parameter set PARAMS into BUF and update LENGTH.  */
static gpg_error_t
pack_gost_kdf_params (const gost_kdf_params_t *params,
                      unsigned char *buf, size_t *length)
{
  size_t len = 0;

  if (*length < 1)
    return GPG_ERR_TOO_SHORT;
  buf[len++] = params->vko_algo;
  if (params->vko_algo == VKO_7836)
    {
      if (*length < len + 3)
        return GPG_ERR_TOO_SHORT;
      buf[len++] = params->vko_7836.ukm_len;
      buf[len++] = params->vko_7836.vko_digest_algo;
      buf[len++] = params->vko_7836.vko_digest_params;
    }
  else
    return GPG_ERR_UNKNOWN_ALGORITHM;

  if (*length < len + 1)
    return GPG_ERR_TOO_SHORT;
  buf[len++] = params->kdf_algo;
  if (params->kdf_algo == GOST_KDF_CPDIVERS)
    {
      if (*length < len + 2)
        return GPG_ERR_TOO_SHORT;
      buf[len++] = params->kdf_4357.kdf_cipher_algo;
      buf[len++] = params->kdf_4357.kdf_cipher_params;
    }
  else if (params->kdf_algo != KDF_NULL)
    return GPG_ERR_UNKNOWN_ALGORITHM;

  if (*length < len + 1)
    return GPG_ERR_TOO_SHORT;
  buf[len++] = params->keywrap_algo;
  if (params->keywrap_algo == KEYWRAP_7836)
    {
      if (*length < len + 4)
        return GPG_ERR_TOO_SHORT;
      buf[len++] = params->keywrap_7836.keywrap_mac_algo;
      buf[len++] = params->keywrap_7836.keywrap_mac_params;
      buf[len++] = params->keywrap_7836.keywrap_cipher_algo;
      buf[len++] = params->keywrap_7836.keywrap_cipher_params;
    }
  else
    return GPG_ERR_UNKNOWN_ALGORITHM;

  *length = len;
  return 0;
}

/* Generate default KDF parameters for curve OIDSTR (length QBITS).  */
gpg_error_t
pk_gost_default_params (const char *oidstr, unsigned int qbits,
                        gcry_mpi_t *r_params)
{
  unsigned char buf[64];
  size_t len = sizeof buf - 2;
  gpg_error_t err = GPG_ERR_NO_ERROR;
  int i;

  buf[1] = GOST_KDF_PARAMS_VERSION;
  for (i = 0; i < DIM (gost_kdf_params_table); i++)
    if (!strncmp (oidstr, gost_kdf_params_table[i].oidpfx,
                  strlen (gost_kdf_params_table[i].oidpfx)) &&
        gost_kdf_params_table[i].qbits >= qbits)
      {
        err = pack_gost_kdf_params (&gost_kdf_params_table[i].params,
                                    buf + 2, &len);
        break;
      }
  if (err)
    return err;

  buf[0] = len + 1; /* length byte */
  *r_params = gcry_mpi_set_opaque (*r_params, buf, (len + 2) * 8);
  if (!*r_params)
    err = gpg_error_from_syserror ();
  return err;
}

/* Generate a UKM value for public key PKEY.  */
gpg_error_t
pk_gost_generate_ukm (gcry_mpi_t *pkey, gcry_mpi_t *r_ukm,
                      unsigned int *r_nbits)
{
  gcry_mpi_t paramsmpi;
  const unsigned char *p;
  unsigned int nbits;
  gost_kdf_params_t params;

  *r_ukm = NULL;
  paramsmpi = pkey[2];
  p = gcry_mpi_get_opaque (paramsmpi, &nbits);
  if (!p || nbits < 24)
    return GPG_ERR_BAD_PUBKEY;
  params.vko_algo = VKO_7836;
  params.vko_7836.ukm_len = p[3];
  if (!params.vko_7836.ukm_len)
    return GPG_ERR_TOO_SHORT;

  *r_nbits = params.vko_7836.ukm_len * 8;
  return gost_generate_ukm (*r_nbits, r_ukm);
}

/* Encrypt DATA using shared point SHARED and UKM according to params in PKEY. */
gpg_error_t
pk_gost_encrypt_with_shared_point (gcry_mpi_t shared, gcry_mpi_t ukm,
                                   gcry_mpi_t data, gcry_mpi_t *pkey,
                                   gcry_mpi_t *r_result)
{
  (void)shared; (void)ukm; (void)data; (void)pkey; (void)r_result;
  return GPG_ERR_NOT_IMPLEMENTED;
}

/* Decrypt DATA using shared point SHARED and UKM according to params in PKEY. */
gpg_error_t
pk_gost_decrypt_with_shared_point (gcry_mpi_t shared, gcry_mpi_t ukm,
                                   gcry_mpi_t data, gcry_mpi_t *pkey,
                                   gcry_mpi_t *r_result)
{
  (void)shared; (void)ukm; (void)data; (void)pkey; (void)r_result;
  return GPG_ERR_NOT_IMPLEMENTED;
}
