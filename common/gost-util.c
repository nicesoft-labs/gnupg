/* gost-util.c - Some common code for GOST crypto.
 * Copyright (C) 2019 Paul Wolneykien <manowar@altlinux.org>
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gcrypt.h>
#include <gpg-error.h>
#include "gost-util.h"
#include "util.h"



/* Generate random user keying material (UKM) of ukm_blen bits */
gpg_error_t
gost_generate_ukm(unsigned int ukm_blen, gcry_mpi_t *r_ukm)
{
    if (!*r_ukm)
    {
        *r_ukm = gcry_mpi_new(ukm_blen);
        if (!*r_ukm)
            return gpg_error_from_syserror();
    }

    gcry_mpi_randomize(*r_ukm, ukm_blen, GCRY_STRONG_RANDOM);
    return GPG_ERR_NO_ERROR;
}

/* Helper to set the S-box for ciphers */
static gpg_error_t
set_cipher_sbox(gcry_cipher_hd_t hd, const char *sbox)
{
    char *_sbox;
    gpg_error_t ret;

    if (!sbox)
        return GPG_ERR_NO_ERROR;

    _sbox = xstrdup(sbox);
    if (!_sbox)
        return gpg_error_from_syserror();

    ret = gcry_cipher_ctl(hd, GCRYCTL_SET_SBOX, _sbox, strlen(_sbox));
    xfree(_sbox);
    return ret;
}

/* Helper to set the S-box for MACs */
static gpg_error_t
set_mac_sbox(gcry_mac_hd_t hd, const char *sbox)
{
    char *_sbox;
    gpg_error_t ret;

    if (!sbox)
        return GPG_ERR_NO_ERROR;

    _sbox = xstrdup(sbox);
    if (!_sbox)
        return gpg_error_from_syserror();

    ret = gcry_mac_ctl(hd, GCRYCTL_SET_SBOX, _sbox, strlen(_sbox));
    xfree(_sbox);
    return ret;
}

/**
 * Diversifies the key using the given UKM.
 * Implements RFC 4357 p.6.5 key diversification algorithm.
 *
 * @param result      MPI to store the diversified key
 * @param cipher_algo Cipher algorithm
 * @param cipher_sbox Cipher S-box parameters
 * @param key         session key buffer
 * @param key_len     length of key in bytes
 * @param ukm         user key material MPI
 */
gpg_error_t
gost_cpdiversify_key(gcry_mpi_t *result,
                     enum gcry_cipher_algos cipher_algo,
                     const char *cipher_sbox,
                     const unsigned char *key, size_t key_len,
                     gcry_mpi_t ukm)
{
    gpg_error_t ret = GPG_ERR_NO_ERROR;
    gcry_cipher_hd_t hd = NULL;
    unsigned char *ukm_buf = NULL;
    size_t ukm_len = 0;
    unsigned int ukm_blen = 0;
    unsigned char *_ukm_buf = NULL;
    unsigned char *result_buf = NULL;
    int i, j, mask;
    u32 k, s1, s2;
    unsigned char S[8];

    if (gcry_mpi_get_flag(ukm, GCRYMPI_FLAG_OPAQUE))
    {
        _ukm_buf = gcry_mpi_get_opaque(ukm, &ukm_blen);
        ukm_len = (ukm_blen + 7) / 8;
        if (_ukm_buf)
            ukm_buf = xtrymalloc(ukm_len);
        if (ukm_buf)
            memcpy(ukm_buf, _ukm_buf, ukm_len);
    }
    else
    {
        ret = gcry_mpi_aprint(GCRYMPI_FMT_USG, &ukm_buf, &ukm_len, ukm);
        if (ret != GPG_ERR_NO_ERROR)
            goto exit;
    }

    flip_buffer(ukm_buf, ukm_len);

    if (ukm_len < 8)
    {
        ret = GPG_ERR_TOO_SHORT;
        goto exit;
    }

    result_buf = xtrymalloc_secure(key_len);
    if (!result_buf)
    {
        ret = gpg_error_from_syserror();
        goto exit;
    }

    ret = gcry_cipher_open(&hd, cipher_algo, GCRY_CIPHER_MODE_CFB, 0);
    if (ret != GPG_ERR_NO_ERROR)
        goto exit;

    memcpy(result_buf, key, key_len);

    for (i = 0; i < 8; i++)
    {
        s1 = 0; s2 = 0;
        for (j = 0, mask = 1; j < 8; j++, mask <<= 1)
        {
            k = ((u32)result_buf[4 * j]) |
                (result_buf[4 * j + 1] << 8) |
                (result_buf[4 * j + 2] << 16) |
                (result_buf[4 * j + 3] << 24);
            if (mask & ukm_buf[i])
                s1 += k;
            else
                s2 += k;
        }
        S[0] = (unsigned char)(s1 & 0xff);
        S[1] = (unsigned char)((s1 >> 8) & 0xff);
        S[2] = (unsigned char)((s1 >> 16) & 0xff);
        S[3] = (unsigned char)((s1 >> 24) & 0xff);
        S[4] = (unsigned char)(s2 & 0xff);
        S[5] = (unsigned char)((s2 >> 8) & 0xff);
        S[6] = (unsigned char)((s2 >> 16) & 0xff);
        S[7] = (unsigned char)((s2 >> 24) & 0xff);

        ret = gcry_cipher_reset(hd);
        if (ret != GPG_ERR_NO_ERROR) goto exit;
        ret = gcry_cipher_setkey(hd, result_buf, key_len);
        if (ret != GPG_ERR_NO_ERROR) goto exit;
        ret = gcry_cipher_setiv(hd, S, sizeof S);
        if (ret != GPG_ERR_NO_ERROR) goto exit;
        ret = set_cipher_sbox(hd, cipher_sbox);
        if (ret != GPG_ERR_NO_ERROR) goto exit;

        ret = gcry_cipher_encrypt(hd, result_buf, key_len, NULL, 0);
        if (ret != GPG_ERR_NO_ERROR) goto exit;
    }

    *result = gcry_mpi_set_opaque_copy(*result, result_buf, 8 * key_len);

exit:
    if (hd)         gcry_cipher_close(hd);
    xfree(ukm_buf);
    xfree(result_buf);
    return ret;
}

/**
 * Wraps the key using RFC 4357 6.3 or RFC 7836 4.6.
 * The UKM value is not included in the result; passed separately.
 */
gpg_error_t
gost_keywrap(gcry_mpi_t *result,
             enum gcry_cipher_algos cipher_algo,
             const char *cipher_sbox,
             enum gcry_mac_algos mac_algo,
             const char *mac_sbox,
             gcry_mpi_t key, gcry_mpi_t ukm, gcry_mpi_t kek)
{
    gpg_error_t err = GPG_ERR_NO_ERROR;
    gcry_cipher_hd_t cipher_hd = NULL;
    gcry_mac_hd_t mac_hd = NULL;
    unsigned char *ekey_buf = NULL;
    unsigned char *result_buf = NULL;
    unsigned char *ukm_buf = NULL;
    size_t keylen, mac_len, result_len, ukm_len;
    unsigned char *kek_buf = NULL;
    unsigned int kek_nbits, kek_len;
    unsigned int ukm_blen = 0;
    unsigned char *_ukm_buf = NULL;
    size_t ukm_wrt = 0;

    keylen = (gcry_mpi_get_nbits(key) + 7) / 8;
    mac_len = gcry_mac_get_algo_maclen(mac_algo);
    result_len = keylen + mac_len;

    result_buf = xmalloc(result_len);
    if (!result_buf)
    {
        err = gpg_error_from_syserror();
        goto exit;
    }
    ekey_buf = xtrymalloc_secure(keylen);
    if (!ekey_buf)
    {
        err = gpg_error_from_syserror();
        goto exit;
    }

    ukm_len = (gcry_mpi_get_nbits(ukm) + 7) / 8;
    ukm_buf = xmalloc(ukm_len);
    if (!ukm_buf)
    {
        err = gpg_error_from_syserror();
        goto exit;
    }

    err = gcry_cipher_open(&cipher_hd, cipher_algo, GCRY_CIPHER_MODE_ECB, 0);
    if (err != GPG_ERR_NO_ERROR) goto exit;
    err = set_cipher_sbox(cipher_hd, cipher_sbox);
    if (err != GPG_ERR_NO_ERROR) goto exit;

    err = gcry_mpi_print(GCRYMPI_FMT_USG, ekey_buf, keylen, NULL, key);
    if (err != GPG_ERR_NO_ERROR) goto exit;
    err = gcry_cipher_encrypt(cipher_hd, result_buf, keylen, ekey_buf, keylen);
    if (err != GPG_ERR_NO_ERROR) goto exit;

    if (gcry_mpi_get_flag(ukm, GCRYMPI_FLAG_OPAQUE))
    {
        _ukm_buf = gcry_mpi_get_opaque(ukm, &ukm_blen);
        if (_ukm_buf)
            memcpy(ukm_buf, _ukm_buf, ukm_len);
    }
    else
    {
        err = gcry_mpi_print(GCRYMPI_FMT_USG, ukm_buf, ukm_len, &ukm_wrt, ukm);
        if (err != GPG_ERR_NO_ERROR) goto exit;
        if (ukm_wrt < ukm_len)
        {
            memmove(ukm_buf + (ukm_len - ukm_wrt), ukm_buf, ukm_wrt);
            memset(ukm_buf, 0, ukm_len - ukm_wrt);
        }
    }
    flip_buffer(ukm_buf, ukm_len);

    err = gcry_mac_open(&mac_hd, mac_algo, 0, NULL);
    if (err != GPG_ERR_NO_ERROR) goto exit;
    err = set_mac_sbox(mac_hd, mac_sbox);
    if (err != GPG_ERR_NO_ERROR) goto exit;

    /* Extract KEK bytes */
    kek_buf = gcry_mpi_get_opaque(kek, &kek_nbits);
    if (!kek_buf)
    {
        err = gpg_error_from_syserror();
        goto exit;
    }
    kek_len = (kek_nbits + 7) / 8;

    err = gcry_mac_setkey(mac_hd, kek_buf, kek_len);
    if (err != GPG_ERR_NO_ERROR) goto exit;
    err = gcry_mac_setiv(mac_hd, ukm_buf, ukm_len);
    if (err != GPG_ERR_NO_ERROR) goto exit;
    err = gcry_mac_write(mac_hd, ekey_buf, keylen);
    if (err != GPG_ERR_NO_ERROR) goto exit;
    err = gcry_mac_read(mac_hd, result_buf + keylen, &mac_len);
    if (err != GPG_ERR_NO_ERROR) goto exit;

    *result = gcry_mpi_set_opaque_copy(*result, result_buf, 8 * result_len);

exit:
    if (cipher_hd) gcry_cipher_close(cipher_hd);
    if (mac_hd)    gcry_mac_close(mac_hd);
    xfree(ekey_buf);
    xfree(result_buf);
    xfree(ukm_buf);
    return err;
}

/* Compute VKO-2012 key from SHARED using DIGEST_ALGO and optional
 * DIGEST_PARAMS.  On success store the derived key at KEYOUT and its
 * length at KEYOUT_LEN.  */
gpg_error_t
gost_vko (gcry_mpi_t shared, enum gcry_md_algos digest_algo,
          const char *digest_params, unsigned char **keyout,
          size_t *keyout_len)
{
  unsigned char *secret = NULL;
  gcry_md_hd_t md = NULL;
  unsigned char *_keyout = NULL;
  gpg_error_t ret = GPG_ERR_NO_ERROR;
  size_t secret_len;

  switch (digest_algo)
    {
    case GCRY_MD_GOSTR3411_94:
      if (!digest_params || strcmp (digest_params, "1.2.643.2.2.30.1"))
        ret = GPG_ERR_DIGEST_ALGO;
      else
        digest_algo = GCRY_MD_GOSTR3411_CP;
      break;
    case GCRY_MD_GOSTR3411_CP:
      if (digest_params && strcmp (digest_params, "1.2.643.2.2.30.1"))
        ret = GPG_ERR_DIGEST_ALGO;
      break;
    case GCRY_MD_STRIBOG256:
    case GCRY_MD_STRIBOG512:
      if (digest_params)
        ret = GPG_ERR_DIGEST_ALGO;
      break;
    default:
      ret = GPG_ERR_DIGEST_ALGO;
    }

  if (ret)
    {
      log_error ("Wrong digest parameters for VKO 7836\n");
      return ret;
    }

  secret_len = (gcry_mpi_get_nbits (shared) + 7) / 8;
  secret = xtrymalloc_secure (secret_len);
  if (!secret)
    return gpg_error_from_syserror ();

  ret = gcry_mpi_print (GCRYMPI_FMT_USG, secret, secret_len, NULL, shared);
  if (ret)
    goto leave;

  if (secret_len % 2)
    {
      memmove (secret, secret + 1, secret_len - 1);
      secret_len -= 1;
    }

  flip_buffer (secret, secret_len/2);
  flip_buffer (secret + secret_len/2, secret_len/2);

  ret = gcry_md_open (&md, digest_algo, GCRY_MD_FLAG_SECURE);
  if (ret)
    goto leave;

  gcry_md_write (md, secret, secret_len);

  {
    size_t dlen = gcry_md_get_algo_dlen (digest_algo);
    if (*keyout && (!keyout_len || *keyout_len < dlen))
      {
        ret = GPG_ERR_TOO_SHORT;
        goto leave;
      }

    _keyout = gcry_md_read (md, digest_algo);
    if (!_keyout)
      {
        ret = gpg_error_from_syserror ();
        goto leave;
      }

    if (!*keyout)
      {
        *keyout = xtrymalloc_secure (dlen);
        if (!*keyout)
          {
            ret = gpg_error_from_syserror ();
            goto leave;
          }
      }

    memcpy (*keyout, _keyout, dlen);
    if (keyout_len)
      *keyout_len = dlen;
  }

leave:
  xfree (secret);
  gcry_md_close (md);
  if (ret && !*keyout && keyout_len)
    *keyout_len = 0;
  return ret;
}

/* Unwrap a key wrapped by gost_keywrap.  */
gpg_error_t
gost_keyunwrap (gcry_mpi_t *result,
                enum gcry_cipher_algos cipher_algo,
                const char *cipher_sbox,
                enum gcry_mac_algos mac_algo,
                const char *mac_sbox,
                const unsigned char *wrapped, size_t wrapped_len,
                gcry_mpi_t ukm, gcry_mpi_t kek)
{
  gpg_error_t err = 0;
  gcry_cipher_hd_t cipher_hd = NULL;
  gcry_mac_hd_t mac_hd = NULL;
  unsigned char *ukm_buf = NULL;
  unsigned char *result_buf = NULL;
  size_t ukm_len;
  size_t mac_len = gcry_mac_get_algo_maclen (mac_algo);
  size_t result_len = wrapped_len - mac_len;

  result_buf = xtrymalloc_secure (result_len);
  if (!result_buf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  ukm_len = (gcry_mpi_get_nbits (ukm) + 7) / 8;
  ukm_buf = xmalloc (ukm_len);
  if (!ukm_buf)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = gcry_cipher_open (&cipher_hd, cipher_algo, GCRY_CIPHER_MODE_ECB, 0);
  if (err)
    goto leave;

  {
    unsigned int kek_nbits;
    unsigned char *kek_buf = gcry_mpi_get_opaque (kek, &kek_nbits);
    unsigned int kek_len = gcry_cipher_get_algo_keylen (cipher_algo);
    if (!kek_buf)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
    if ((kek_nbits + 7)/8 != kek_len)
      {
        err = GPG_ERR_INV_KEYLEN;
        goto leave;
      }
    err = gcry_cipher_setkey (cipher_hd, kek_buf, kek_len);
    if (err)
      goto leave;
  }

  err = set_cipher_sbox (cipher_hd, cipher_sbox);
  if (err)
    goto leave;

  err = gcry_cipher_decrypt (cipher_hd, result_buf, result_len,
                             wrapped, wrapped_len - mac_len);
  if (err)
    goto leave;

  if (gcry_mpi_get_flag (ukm, GCRYMPI_FLAG_OPAQUE))
    {
      unsigned int ukm_blen;
      unsigned char *_ukm = gcry_mpi_get_opaque (ukm, &ukm_blen);
      if (_ukm)
        memcpy (ukm_buf, _ukm, ukm_len);
    }
  else
    {
      size_t ukm_wrt;
      err = gcry_mpi_print (GCRYMPI_FMT_USG, ukm_buf, ukm_len,
                            &ukm_wrt, ukm);
      if (err)
        goto leave;
      if (ukm_wrt < ukm_len)
        {
          memmove (ukm_buf + (ukm_len - ukm_wrt), ukm_buf, ukm_wrt);
          memset (ukm_buf, 0, ukm_len - ukm_wrt);
        }
    }

  flip_buffer (ukm_buf, ukm_len);

  err = gcry_mac_open (&mac_hd, mac_algo, 0, NULL);
  if (err)
    goto leave;

  err = set_mac_sbox (mac_hd, mac_sbox);
  if (err)
    goto leave;

  {
    unsigned int kek_nbits;
    unsigned char *kek_buf = gcry_mpi_get_opaque (kek, &kek_nbits);
    unsigned int kek_len = gcry_cipher_get_algo_keylen (cipher_algo);
    err = gcry_mac_setkey (mac_hd, kek_buf, kek_len);
    if (err)
      goto leave;
  }

  err = gcry_mac_setiv (mac_hd, ukm_buf, ukm_len);
  if (err)
    goto leave;
  err = gcry_mac_write (mac_hd, result_buf, result_len);
  if (err)
    goto leave;
  err = gcry_mac_verify (mac_hd, wrapped + (wrapped_len - mac_len), mac_len);
  if (err)
    goto leave;

  *result = gcry_mpi_set_opaque_copy (*result, result_buf, 8 * result_len);

leave:
  gcry_cipher_close (cipher_hd);
  gcry_mac_close (mac_hd);
  xfree (ukm_buf);
  xfree (result_buf);
  return err;
}
