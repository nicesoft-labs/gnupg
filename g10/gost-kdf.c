/* gost-kdf.c — GOST VKO и KDF по RFC 4357/7836 */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>      /* gcry_mpi_t, gcry_mpi_set_opaque_copy */
#include <gpg-error.h>   /* gpg_error_t, GPG_ERR_* */

#include "../common/openpgpdefs.h"  /* DIGEST_ALGO_*, map_md_openpgp_to_gcry */
#include "../common/gost-util.h"    /* gost_cpdiversify_key, gost_vko */
#include "../common/util.h"         /* xtrycalloc, xfree */

#include "gost-kdf.h"   /* gost_kdf_params_t, VKO_*, KDF_*, KEYWRAP_* */
#include "gost-map.h"   /* map_gost_cipher_openpgp_to_gcry, cipher_params_to_sbox */

/* Преобразование digest_params_t → OID */
static const char *
digest_params_to_oid(digest_params_t params)
{
    switch (params) {
    case DIGEST_PARAMS_GOSTR3411_94_A:
        return "1.2.643.2.2.30.1";
    default:
        return NULL;
    }
}

/* Распаковка параметров KDF из буфера */
static gpg_error_t
unpack_gost_kdf_params(const unsigned char *packed,
                       gost_kdf_params_t **r_params)
{
    gost_kdf_params_t *p;
    unsigned int pos = 0;

    p = xtrycalloc(1, sizeof *p);
    if (!p)
        return gpg_error_from_syserror();

    /* VKO */
    p->vko_algo = packed[pos++];
    if (p->vko_algo != VKO_7836) {
        xfree(p);
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }
    p->vko_7836.ukm_len          = packed[pos++];
    p->vko_7836.vko_digest_algo  = packed[pos++];
    p->vko_7836.vko_digest_params= packed[pos++];

    /* KDF */
    p->kdf_algo = packed[pos++];
    switch (p->kdf_algo) {
    case KDF_NULL:
        break;
    case GOST_KDF_CPDIVERS:
        p->kdf_4357.kdf_cipher_algo  = packed[pos++];
        p->kdf_4357.kdf_cipher_params= packed[pos++];
        break;
    default:
        xfree(p);
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }

    /* KeyWrap */
    p->keywrap_algo = packed[pos++];
    if (p->keywrap_algo != KEYWRAP_7836) {
        xfree(p);
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }
    p->keywrap_7836.keywrap_mac_algo     = packed[pos++];
    p->keywrap_7836.keywrap_mac_params   = packed[pos++];
    p->keywrap_7836.keywrap_cipher_algo  = packed[pos++];
    p->keywrap_7836.keywrap_cipher_params= packed[pos++];

    *r_params = p;
    return 0;
}

/* Освобождение структуры параметров */
void
free_gost_kdf_params(gost_kdf_params_t *p)
{
    xfree(p);
}

/* Заглушка для древовидного KDF (не реализован) */
static gpg_error_t
kdf_tree_notimpl(void)
{
    return GPG_ERR_UNSUPPORTED_ALGORITHM;
}

/* Основной KDF: из UKM + shared_buf → shared KEK */
gpg_error_t
gost_kdf(const gost_kdf_params_t *params,
         gcry_mpi_t ukm,
         const unsigned char *shared_buf,
         size_t shared_len,
         gcry_mpi_t *out_kek)
{
    switch (params->kdf_algo) {
    case KDF_NULL:
        *out_kek = gcry_mpi_set_opaque_copy(
            *out_kek, shared_buf, 8 * shared_len);
        return 0;

    case GOST_KDF_CPDIVERS:
        return gost_cpdiversify_key(
            out_kek,
            map_gost_cipher_openpgp_to_gcry(params->kdf_4357.kdf_cipher_algo),
            cipher_params_to_sbox(params->kdf_4357.kdf_cipher_params),
            shared_buf, shared_len, ukm);

    case GOST_KDF_TREE:
        return kdf_tree_notimpl();

    default:
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

/* VKO + KDF: сначала VKO, затем gost_kdf */
gpg_error_t
gost_vko_kdf(const gost_kdf_params_t *params,
             gcry_mpi_t shared,
             gcry_mpi_t ukm,
             gcry_mpi_t *out_kek)
{
    gpg_error_t ret;
    unsigned char *buf = NULL;
    size_t buflen = 0;

    if (params->vko_algo != VKO_7836)
        return GPG_ERR_UNKNOWN_ALGORITHM;

    ret = gost_vko(
        shared,
        map_md_openpgp_to_gcry(params->vko_7836.vko_digest_algo),
        digest_params_to_oid(params->vko_7836.vko_digest_params),
        &buf, &buflen);
    if (ret) {
        xfree(buf);
        return ret;
    }

    ret = gost_kdf(params, ukm, buf, buflen, out_kek);
    xfree(buf);
    return ret;
}
