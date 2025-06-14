/* gost-helper.c — извлечение параметров KDF/VKO из публичного ключа */
#include <config.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>      /* gcry_mpi_get_opaque */
#include <gpg-error.h>   /* gpg_error_t, GPG_ERR_* */

#include "../common/util.h"        /* xtrycalloc, xfree */
#include "gost-kdf.h"              /* gost_kdf_params_t, VKO_*, KDF_*, KEYWRAP_* */
#include "gost-helper.h"           /* pk_gost_get_kdf_params */

/* Распаковать байтовый буфер packed → структуру gost_kdf_params_t */
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
    p->vko_7836.ukm_len           = packed[pos++];
    p->vko_7836.vko_digest_algo   = packed[pos++];
    p->vko_7836.vko_digest_params = packed[pos++];

    /* KDF */
    p->kdf_algo = packed[pos++];
    switch (p->kdf_algo) {
    case KDF_NULL:
        break;
    case GOST_KDF_CPDIVERS:
        p->kdf_4357.kdf_cipher_algo   = packed[pos++];
        p->kdf_4357.kdf_cipher_params = packed[pos++];
        break;
    case GOST_KDF_TREE:
        xfree(p);
        return GPG_ERR_UNSUPPORTED_ALGORITHM;
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

/* Извлечь параметры KDF/VKO из массива MPI публичного ключа (OID + данные) */
gpg_error_t
pk_gost_get_kdf_params(gcry_mpi_t *pkey, gost_kdf_params_t **r_params)
{
    const unsigned char *raw;
    size_t size;
    unsigned int nbits;

    /* MPI[2] — это закодированные параметры (opaque) */
    raw = gcry_mpi_get_opaque(pkey[2], &nbits);
    size = (nbits + 7) / 8;

    /* Версия должна быть в raw[1] */
    if (size < 3 || raw[1] != GOST_KDF_PARAMS_VERSION)
        return GPG_ERR_BAD_PUBKEY;

    /* unpack — начиная с raw+2, длиной size-2 */
    return unpack_gost_kdf_params(raw + 2, r_params);
}
