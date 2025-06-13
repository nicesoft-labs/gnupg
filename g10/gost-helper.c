#include <config.h>
#include <string.h>

#include "gost-helper.h"
#include "../common/util.h"

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
      p->vko_7836.ukm_len = packed[pos++];
      p->vko_7836.vko_digest_algo = packed[pos++];
      p->vko_7836.vko_digest_params = packed[pos++];
      break;
    default:
      ret = GPG_ERR_UNKNOWN_ALGORITHM;
      goto fail;
    }

  p->kdf_algo = packed[pos++];
  switch (p->kdf_algo)
    {
    case GOST_KDF_CPDIVERS:
      p->kdf_4357.kdf_cipher_algo = packed[pos++];
      p->kdf_4357.kdf_cipher_params = packed[pos++];
      break;
    case KDF_NULL:
      break;
    case GOST_KDF_TREE:
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
      p->keywrap_7836.keywrap_mac_algo = packed[pos++];
      p->keywrap_7836.keywrap_mac_params = packed[pos++];
      p->keywrap_7836.keywrap_cipher_algo = packed[pos++];
      p->keywrap_7836.keywrap_cipher_params = packed[pos++];
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

/* Extract VKO/KDF parameters from a public key MPI array.  */
gpg_error_t
pk_gost_get_kdf_params (gcry_mpi_t *pkey, gost_kdf_params_t **r_params)
{
  const unsigned char *p;
  size_t size;
  unsigned int nbits;

  p = gcry_mpi_get_opaque (pkey[2], &nbits);
  size = (nbits + 7)/8;
  if (size > 2 && p[1] != GOST_KDF_PARAMS_VERSION)
    return GPG_ERR_BAD_PUBKEY;

  return unpack_gost_kdf_params ((unsigned char*)p + 2, r_params);
}

