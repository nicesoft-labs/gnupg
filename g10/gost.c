#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <gpg-error.h>

#include "../common/util.h"
#include "../common/gost-util.h"
#include "../common/openpgpdefs.h"

#include "pkglue.h"
#include "gost-kdf.h"
#include "gost-map.h"
#include "gost-helper.h"

#ifndef DBG_CRYPTO
# define DBG_CRYPTO 0
#endif

#define GOST_KDF_PARAMS_VERSION 2

/* Default parameter table for supported curves. */
static const struct {
    const char       *oidpfx;
    unsigned int      qbits;
    gost_kdf_params_t params;
} gost_kdf_params_table[] = {{
    "1.2.643.7.1.2.1.1.", 256,
    {
        .vko_algo = VKO_7836,
        .vko_7836 = { 8, DIGEST_ALGO_GOSTR3411_12_256, DIGEST_PARAMS_UNSPECIFIED },
        .kdf_algo = GOST_KDF_CPDIVERS,
        .kdf_4357 = { CIPHER_ALGO_GOST28147, CIPHER_PARAMS_GOST28147_Z },
        .keywrap_algo = KEYWRAP_7836,
        .keywrap_7836 = { MAC_ALGO_GOST28147_IMIT, MAC_PARAMS_GOST28147_Z,
                          CIPHER_ALGO_GOST28147, CIPHER_PARAMS_GOST28147_Z }
    }
}, {
    "1.2.643.7.1.2.1.2.", 512,
    {
        .vko_algo = VKO_7836,
        .vko_7836 = { 8, DIGEST_ALGO_GOSTR3411_12_256, DIGEST_PARAMS_UNSPECIFIED },
        .kdf_algo = GOST_KDF_CPDIVERS,
        .kdf_4357 = { CIPHER_ALGO_GOST28147, CIPHER_PARAMS_GOST28147_Z },
        .keywrap_algo = KEYWRAP_7836,
        .keywrap_7836 = { MAC_ALGO_GOST28147_IMIT, MAC_PARAMS_GOST28147_Z,
                          CIPHER_ALGO_GOST28147, CIPHER_PARAMS_GOST28147_Z }
    }
}};

static gpg_error_t pack_gost_kdf_params(const gost_kdf_params_t *params,
                                        unsigned char *buf,
                                        size_t *lenp)
{
    size_t len = 0;

    if (*lenp < 1)
        return GPG_ERR_TOO_SHORT;
    buf[len++] = params->vko_algo;
    if (params->vko_algo != VKO_7836)
        return GPG_ERR_UNKNOWN_ALGORITHM;
    if (*lenp < len + 3)
        return GPG_ERR_TOO_SHORT;
    buf[len++] = params->vko_7836.ukm_len;
    buf[len++] = params->vko_7836.vko_digest_algo;
    buf[len++] = params->vko_7836.vko_digest_params;

    if (*lenp < len + 1)
        return GPG_ERR_TOO_SHORT;
    buf[len++] = params->kdf_algo;
    if (params->kdf_algo == GOST_KDF_CPDIVERS) {
        if (*lenp < len + 2)
            return GPG_ERR_TOO_SHORT;
        buf[len++] = params->kdf_4357.kdf_cipher_algo;
        buf[len++] = params->kdf_4357.kdf_cipher_params;
    } else if (params->kdf_algo != KDF_NULL)
        return GPG_ERR_UNKNOWN_ALGORITHM;

    if (*lenp < len + 1)
        return GPG_ERR_TOO_SHORT;
    buf[len++] = params->keywrap_algo;
    if (params->keywrap_algo != KEYWRAP_7836)
        return GPG_ERR_UNKNOWN_ALGORITHM;
    if (*lenp < len + 4)
        return GPG_ERR_TOO_SHORT;
    buf[len++] = params->keywrap_7836.keywrap_mac_algo;
    buf[len++] = params->keywrap_7836.keywrap_mac_params;
    buf[len++] = params->keywrap_7836.keywrap_cipher_algo;
    buf[len++] = params->keywrap_7836.keywrap_cipher_params;

    *lenp = len;
    return 0;
}

/* Generate default KDF parameters for curve OIDSTR */
gpg_error_t pk_gost_default_params(const char *oidstr,
                                   unsigned int qbits,
                                   gcry_mpi_t *r_params)
{
    unsigned char buf[64];
    size_t len = sizeof(buf) - 2;
    gpg_error_t err = GPG_ERR_NO_ERROR;
    unsigned i;

    buf[1] = GOST_KDF_PARAMS_VERSION;
    for (i = 0; i < DIM(gost_kdf_params_table); i++) {
        if (!strncmp(oidstr, gost_kdf_params_table[i].oidpfx,
                     strlen(gost_kdf_params_table[i].oidpfx)) &&
            gost_kdf_params_table[i].qbits >= qbits) {
            err = pack_gost_kdf_params(&gost_kdf_params_table[i].params,
                                        buf + 2, &len);
            break;
        }
    }
    if (err)
        return err;

    buf[0] = len + 1;
    *r_params = gcry_mpi_set_opaque(*r_params, buf, (len + 2) * 8);
    return *r_params ? GPG_ERR_NO_ERROR : gpg_error_from_syserror();
}

/* Generate UKM for public key PKEY */
gpg_error_t pk_gost_generate_ukm(gcry_mpi_t *pkey,
                                  gcry_mpi_t *r_ukm,
                                  unsigned int *r_nbits)
{
    const unsigned char *p;
    unsigned int nbits;

    *r_ukm = NULL;
    p = gcry_mpi_get_opaque(pkey[2], &nbits);
    if (!p || nbits < 24)
        return GPG_ERR_BAD_PUBKEY;

    *r_nbits = p[3] * 8;
    return gost_generate_ukm(*r_nbits, r_ukm);
}

/* Encrypt DATA using SHARED and UKM per params in PKEY */
gpg_error_t pk_gost_encrypt_with_shared_point(gcry_mpi_t shared,
                                               gcry_mpi_t ukm,
                                               gcry_mpi_t data,
                                               gcry_mpi_t *pkey,
                                               gcry_mpi_t *r_result)
{
    gost_kdf_params_t *kdf_params;
    gcry_mpi_t kek = NULL, encoded_key = NULL;
    unsigned char *encbuf = NULL;
    unsigned int enc_blen;
    size_t enclen;
    gpg_error_t ret;

    if (DBG_CRYPTO) {
        log_printmpi("GOST unwrapped:", data);
        log_printmpi("GOST UKM:", ukm);
        log_printmpi("GOST shared:", shared);
    }

    *r_result = NULL;
    ret = pk_gost_get_kdf_params(pkey, &kdf_params);
    if (ret)
        return ret;

    ret = gost_vko_kdf(kdf_params, shared, ukm, &kek);
    if (ret)
        goto cleanup;

    if (DBG_CRYPTO)
        log_printmpi("GOST KEK:", kek);

    if (kdf_params->keywrap_algo != KEYWRAP_7836) {
        ret = GPG_ERR_UNKNOWN_ALGORITHM;
        goto cleanup;
    }

    ret = gost_keywrap(&encoded_key,
                       map_gost_cipher_openpgp_to_gcry(
                         kdf_params->keywrap_7836.keywrap_cipher_algo),
                       cipher_params_to_sbox(
                         kdf_params->keywrap_7836.keywrap_cipher_params),
                       map_mac_openpgp_to_gcry(
                         kdf_params->keywrap_7836.keywrap_mac_algo),
                       mac_params_to_sbox(
                         kdf_params->keywrap_7836.keywrap_mac_params),
                       data, ukm, kek);
    if (ret)
        goto cleanup;

    encbuf = (unsigned char*)gcry_mpi_get_opaque(encoded_key, &enc_blen);
    enclen = (enc_blen + 7) / 8;
    if (enclen > 255) {
        ret = GPG_ERR_TOO_LARGE;
        goto cleanup;
    }

    encbuf = xtrymalloc(enclen + 1);
    if (!encbuf) {
        ret = gpg_error_from_syserror();
        goto cleanup;
    }
    encbuf[0] = (unsigned char)enclen;
    memcpy(encbuf + 1, (unsigned char*)gcry_mpi_get_opaque(encoded_key, NULL), enclen);

    *r_result = gcry_mpi_set_opaque(*r_result, encbuf, (enclen + 1) * 8);
    if (!*r_result)
        ret = gpg_error_from_syserror();

cleanup:
    free_gost_kdf_params(kdf_params);
    gcry_mpi_release(kek);
    gcry_mpi_release(encoded_key);
    if (encbuf && !*r_result)
        xfree(encbuf);
    return ret;
}

/* Decrypt DATA using SHARED and UKM per params in PKEY */
gpg_error_t pk_gost_decrypt_with_shared_point(gcry_mpi_t shared,
                                               gcry_mpi_t ukm,
                                               gcry_mpi_t data,
                                               gcry_mpi_t *pkey,
                                               gcry_mpi_t *r_result)
{
    gost_kdf_params_t *kdf_params;
    gcry_mpi_t kek = NULL;
    const unsigned char *data_buf;
    unsigned int data_bits;
    size_t data_len;
    gpg_error_t ret;

    if (DBG_CRYPTO)
        log_printmpi("GOST encrypted:", data);

    *r_result = NULL;
    data_buf = gcry_mpi_get_opaque(data, &data_bits);
    if (!data_buf) {
        return gpg_error_from_syserror();
    }
    data_len = (data_bits + 7) / 8;
    if (data_buf[0] != (unsigned char)(data_len - 1))
        return GPG_ERR_BAD_MPI;

    if (DBG_CRYPTO)
        log_printhex(data_buf + 1, data_len - 1, "GOST wrapped:");

    ret = pk_gost_get_kdf_params(pkey, &kdf_params);
    if (ret)
        return ret;

    if (gcry_mpi_get_nbits(shared) < gcry_mpi_get_nbits(pkey[1])) {
        /* direct KEK case */
        unsigned char *kek_buf;
        size_t shared_len = (gcry_mpi_get_nbits(shared) + 7) / 8;
        kek_buf = xtrymalloc_secure(shared_len);
        if (!kek_buf) {
            ret = gpg_error_from_syserror();
            goto cleanup;
        }
        ret = gcry_mpi_print(GCRYMPI_FMT_USG, kek_buf, shared_len, NULL, shared);
        if (ret) {
            xfree(kek_buf);
            goto cleanup;
        }
        ret = gost_kdf(kdf_params, ukm, kek_buf, shared_len, &kek);
        xfree(kek_buf);
    } else {
        /* normal VKO case */
        ret = gost_vko_kdf(kdf_params, shared, ukm, &kek);
    }
    if (ret)
        goto cleanup;

    if (kdf_params->keywrap_algo != KEYWRAP_7836) {
        ret = GPG_ERR_UNKNOWN_ALGORITHM;
        goto cleanup;
    }

    ret = gost_keyunwrap(r_result,
                         map_gost_cipher_openpgp_to_gcry(
                           kdf_params->keywrap_7836.keywrap_cipher_algo),
                         cipher_params_to_sbox(
                           kdf_params->keywrap_7836.keywrap_cipher_params),
                         map_mac_openpgp_to_gcry(
                           kdf_params->keywrap_7836.keywrap_mac_algo),
                         mac_params_to_sbox(
                           kdf_params->keywrap_7836.keywrap_mac_params),
                         data_buf + 1, data_len - 1, ukm, kek);
    if (ret)
        goto cleanup;

    if (DBG_CRYPTO)
        log_printmpi("GOST unwrapped:", *r_result);

cleanup:
    free_gost_kdf_params(kdf_params);
    gcry_mpi_release(kek);
    return ret;
}
