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
#include "gost-kdf.h"
#include "gost-map.h"
#include "gost-helper.h"

#ifndef DBG_CRYPTO
# define DBG_CRYPTO 0
#endif

/* Version marker used with packed GOST parameter sets.  */
#define GOST_KDF_PARAMS_VERSION 2

/* Parameter descriptors moved to gost-kdf.h */

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
  gost_kdf_params_t *kdf_params = NULL;
  gcry_mpi_t kek = NULL;
  gcry_mpi_t encoded_key = NULL;
  unsigned char *encbuf = NULL;
  gpg_error_t ret = GPG_ERR_NO_ERROR;

  if (DBG_CRYPTO)
    {
      log_printmpi ("GOST unwrapped value:", data);
      log_printmpi ("GOST UKM:", ukm);
      log_printmpi ("GOST shared point:", shared);
    }

  *r_result = NULL;

  ret = pk_gost_get_kdf_params (pkey, &kdf_params);
  if (ret != GPG_ERR_NO_ERROR)
    return ret;

  ret = gost_vko_kdf (kdf_params, shared, ukm, &kek);
  if (ret != GPG_ERR_NO_ERROR)
    goto exit;

  if (DBG_CRYPTO)
    log_printmpi ("GOST KEK:", kek);

  switch (kdf_params->keywrap_algo)
    {
    case KEYWRAP_7836:
      ret = gost_keywrap (&encoded_key,
                          map_cipher_openpgp_to_gcry (kdf_params->keywrap_params.keywrap_7836.keywrap_cipher_algo),
                          cipher_params_to_sbox (kdf_params->keywrap_params.keywrap_7836.keywrap_cipher_params),
                          map_mac_openpgp_to_gcry (kdf_params->keywrap_params.keywrap_7836.keywrap_mac_algo),
                          mac_params_to_sbox (kdf_params->keywrap_params.keywrap_7836.keywrap_mac_params),
                          data, ukm, kek);
      break;
    default:
      ret = GPG_ERR_UNKNOWN_ALGORITHM;
    }
  if (ret != GPG_ERR_NO_ERROR)
    goto exit;

  if (DBG_CRYPTO)
    log_printmpi ("GOST wrapped value:", encoded_key);

  unsigned int enc_blen;
  unsigned char *encoded_key_buf = gcry_mpi_get_opaque (encoded_key, &enc_blen);
  size_t enclen = (enc_blen+7)/8;
  if (enclen > 255)
    {
      ret = GPG_ERR_TOO_LARGE;
      goto exit;
    }

  encbuf = xmalloc (enclen + 1);
  if (!encbuf)
    {
      ret = gpg_error_from_syserror ();
      goto exit;
    }

  encbuf[0] = (unsigned char) enclen;
  memcpy (encbuf + 1, encoded_key_buf, enclen);

  *r_result = gcry_mpi_set_opaque (*r_result, encbuf, (enclen + 1) * 8);

  if (DBG_CRYPTO)
    log_printmpi ("GOST encrypted value:", *r_result);

 exit:
  free_gost_kdf_params (kdf_params);
  gcry_mpi_release (kek);
  gcry_mpi_release (encoded_key);

  if (!*r_result)
    xfree (encbuf);

  return ret;
}

/* Decrypt DATA using shared point SHARED and UKM according to params in PKEY. */
gpg_error_t
pk_gost_decrypt_with_shared_point (gcry_mpi_t shared, gcry_mpi_t ukm,
                                   gcry_mpi_t data, gcry_mpi_t *pkey,
                                   gcry_mpi_t *r_result)
{
  gost_kdf_params_t *kdf_params = NULL;
  gcry_mpi_t kek = NULL;
  unsigned char *data_buf = NULL;
  gpg_error_t ret = GPG_ERR_NO_ERROR;

  if (DBG_CRYPTO)
    log_printmpi ("GOST encrypted value:", data);

  *r_result = NULL;

  unsigned int data_bits;
  data_buf = gcry_mpi_get_opaque (data, &data_bits);
  if (!data_buf)
    {
      ret = gpg_error_from_syserror ();
      goto exit;
    }

  byte data_len = (byte) ((data_bits + 7)/8);
  if (data_buf[0] != (data_len - 1))
    {
      ret = GPG_ERR_BAD_MPI;
      goto exit;
    }

  if (DBG_CRYPTO)
    {
      log_printhex (data_buf + 1, data_len - 1, "GOST wrapped value:");
      log_printmpi ("GOST UKM:", ukm);
    }

  ret = pk_gost_get_kdf_params (pkey, &kdf_params);
  if (ret != GPG_ERR_NO_ERROR)
    return ret;

  unsigned int shared_blen = gcry_mpi_get_nbits (shared);
  if (shared_blen < gcry_mpi_get_nbits (pkey[1]))
    {
      if (DBG_CRYPTO)
        log_debug ("GOST shared point: --\n");

      /* It seems that a KEK is directly passed here, possibly from
         a hardware token or card. */
      unsigned char shared_len = (shared_blen+7)/8;
      unsigned char *kek_buf = xtrymalloc_secure (shared_len);
      if (!kek_buf)
        {
          ret = gpg_error_from_syserror ();
          goto exit;
        }

      ret = gcry_mpi_print (GCRYMPI_FMT_USG, kek_buf, shared_len, NULL,
                            shared);
      if (ret != GPG_ERR_NO_ERROR)
        goto exit;

      ret = gost_kdf (kdf_params, ukm, kek_buf, shared_len, &kek);
      xfree (kek_buf);

      if (!kek)
        {
          ret = gpg_error_from_syserror ();
          goto exit;
        }
    }
  else
    {
      /* Normal shared point case. */
      if (DBG_CRYPTO)
        log_printmpi ("GOST shared point:", shared);

      ret = gost_vko_kdf (kdf_params, shared, ukm, &kek);
      if (ret != GPG_ERR_NO_ERROR)
        goto exit;
    }

  if (DBG_CRYPTO)
    log_printmpi ("GOST KEK:", kek);

  switch (kdf_params->keywrap_algo)
    {
    case KEYWRAP_7836:
      ret = gost_keyunwrap (r_result,
                            map_cipher_openpgp_to_gcry (kdf_params->keywrap_params.keywrap_7836.keywrap_cipher_algo),
                            cipher_params_to_sbox (kdf_params->keywrap_params.keywrap_7836.keywrap_cipher_params),
                            map_mac_openpgp_to_gcry (kdf_params->keywrap_params.keywrap_7836.keywrap_mac_algo),
                            mac_params_to_sbox (kdf_params->keywrap_params.keywrap_7836.keywrap_mac_params),
                            data_buf + 1, data_len - 1, ukm, kek);
      break;
    default:
      ret = GPG_ERR_UNKNOWN_ALGORITHM;
    }
  if (ret != GPG_ERR_NO_ERROR)
    goto exit;

  if (DBG_CRYPTO)
    log_printmpi ("GOST unwrapped value:", *r_result);

 exit:
  free_gost_kdf_params (kdf_params);
  gcry_mpi_release (kek);

  return ret;
}
