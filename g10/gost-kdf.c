#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "gost-kdf.h"
#include "gost-map.h"
#include "../common/gost-util.h"
#include "../common/util.h"
#include "main.h" /* for map_md_openpgp_to_gcry */

static const char *
digest_params_to_oid (digest_params_t params)
{
  switch (params)
    {
    case DIGEST_PARAMS_GOSTR3411_94_A:
      return "1.2.643.2.2.30.1";
    default:
      return NULL;
    }
}

static gpg_error_t
unpack_gost_kdf_params (unsigned char *packed, gost_kdf_params_t **r_params)
{
  gpg_error_t ret = 0;
  gost_kdf_params_t *p;
  unsigned int pos = 0;

  p = xtrycalloc (1, sizeof *p);
  if (!p)
    return gpg_error_from_syserror ();

  p->vko_algo = packed[pos++];
  switch (p->vko_algo)
    {
    case VKO_7836:
      p->vko_params.vko_7836.ukm_len = packed[pos++];
      p->vko_params.vko_7836.vko_digest_algo = packed[pos++];
      p->vko_params.vko_7836.vko_digest_params = packed[pos++];
      break;
    default:
      ret = GPG_ERR_UNKNOWN_ALGORITHM;
      goto fail;
    }

  p->kdf_algo = packed[pos++];
  switch (p->kdf_algo)
    {
    case GOST_KDF_CPDIVERS:
      p->kdf_params.kdf_4357.kdf_cipher_algo = packed[pos++];
      p->kdf_params.kdf_4357.kdf_cipher_params = packed[pos++];
      break;
    case KDF_NULL:
      break;
    case GOST_KDF_TREE:
      /* not implemented */
      ret = GPG_ERR_UNSUPPORTED_ALGORITHM;
      goto fail;
    default:
      ret = GPG_ERR_UNKNOWN_ALGORITHM;
      goto fail;
    }

  p->keywrap_algo = packed[pos++];
  switch (p->keywrap_algo)
    {
    case KEYWRAP_7836:
      p->keywrap_params.keywrap_7836.keywrap_mac_algo = packed[pos++];
      p->keywrap_params.keywrap_7836.keywrap_mac_params = packed[pos++];
      p->keywrap_params.keywrap_7836.keywrap_cipher_algo = packed[pos++];
      p->keywrap_params.keywrap_7836.keywrap_cipher_params = packed[pos++];
      break;
    default:
      ret = GPG_ERR_UNKNOWN_ALGORITHM;
      goto fail;
    }

  *r_params = p;
  return 0;

 fail:
  xfree (p);
  return ret;
}

void
free_gost_kdf_params (gost_kdf_params_t *p)
{
  if (!p)
    return;
  if (p->kdf_algo == GOST_KDF_TREE && p->kdf_params.kdf_7836.label)
    xfree (p->kdf_params.kdf_7836.label);
  xfree (p);
}

static gpg_error_t
kdf_tree_notimpl (void)
{
  return GPG_ERR_UNSUPPORTED_ALGORITHM;
}

gpg_error_t
gost_kdf (const gost_kdf_params_t *params, gcry_mpi_t ukm,
          const unsigned char *shared_buf, size_t shared_len,
          gcry_mpi_t *out_kek)
{
  gpg_error_t ret = 0;

  switch (params->kdf_algo)
    {
    case KDF_NULL:
      *out_kek = gcry_mpi_set_opaque_copy (*out_kek, shared_buf,
                                           8 * shared_len);
      break;
    case GOST_KDF_CPDIVERS:
      ret = gost_cpdiversify_key (out_kek,
                                  map_cipher_openpgp_to_gcry (params->kdf_params.kdf_4357.kdf_cipher_algo),
                                  cipher_params_to_sbox (params->kdf_params.kdf_4357.kdf_cipher_params),
                                  shared_buf, shared_len, ukm);
      break;
    case GOST_KDF_TREE:
      ret = kdf_tree_notimpl ();
      break;
    default:
      ret = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }
  return ret;
}

gpg_error_t
gost_vko_kdf (const gost_kdf_params_t *params, gcry_mpi_t shared,
              gcry_mpi_t ukm, gcry_mpi_t *out_kek)
{
  gpg_error_t ret = 0;
  unsigned char *buf = NULL;
  size_t buflen = 0;

  switch (params->vko_algo)
    {
    case VKO_7836:
      ret = gost_vko (shared,
                      map_md_openpgp_to_gcry (params->vko_params.vko_7836.vko_digest_algo),
                      digest_params_to_oid (params->vko_params.vko_7836.vko_digest_params),
                      &buf, &buflen);
      break;
    default:
      ret = GPG_ERR_UNKNOWN_ALGORITHM;
      break;
    }
  if (ret)
    {
      xfree (buf);
      return ret;
    }

  ret = gost_kdf (params, ukm, buf, buflen, out_kek);
  xfree (buf);
  return ret;
}

