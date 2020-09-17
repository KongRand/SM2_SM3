//
// Created by iwall on 2020/9/9.
//

#include "../include/sk_sm2.h"

#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../include/sk_sm3.h"
#include "../include/sk_kdf.h"

#define SM2_DEFAULT_POINT_CONVERSION_FORM	POINT_CONVERSION_UNCOMPRESSED

#ifdef CPU_BIGENDIAN
#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#else
#define cpu_to_be16(v) ((v << 8) | (v >> 8))
#define cpu_to_be32(v) ((cpu_to_be16(v) << 16) | cpu_to_be16(v >> 16))
#endif

unsigned char sm2_args[128] = {
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
};


static void sk_printf(unsigned char *src, unsigned int srclen)
{
    printf("\n");
    for (int i = 0; i < srclen; ++i)
    {
        printf("%02x", src[i]);
    }
    printf("\n");
}

/* ZA = H256(ENT LA ∥ IDA ∥ a ∥ b ∥ xG ∥ yG ∥ xA ∥ yA) */
int sk_sm3_z(const unsigned char *id ,int idlen,
             const unsigned char *px, int pxlen,
             const unsigned char *py, int pylen,
             unsigned char *z)
{
    unsigned char *buf = NULL;
    int buflen = 0;

    if ((pxlen > 32) || (pylen > 32))
        return -1;
    buflen = 2 + idlen + sizeof(sm2_args) + pxlen + pylen;
    if (!(buf = calloc(1, buflen)))
        return -1;

    buf[0] = ((idlen << 3) >> 8) & 0xFF;
    buf[1] = (idlen << 3) & 0xFF;

    /* make value */
    memcpy(buf + 2, id, idlen);
    memcpy(buf + 2 + idlen, sm2_args, sizeof(sm2_args));
    memcpy(buf + 2 + idlen + sizeof(sm2_args), px, pxlen);
    memcpy(buf + 2 + idlen + sizeof(sm2_args) + pxlen, py, pylen);
    SM3(buf, buflen, z);
    free(buf);
    return 0;
}

/* e′ = H256(M′) */
int sk_sm3_e(const unsigned char *id, int idlen,
             const unsigned char *px, int pxlen,
             const unsigned char *py, int pylen,
             const unsigned char *msg, int msglen,
             unsigned char *e)
{
    unsigned char *buf = NULL;
    int buflen = 0;
    unsigned char z[SM3_DIGEST_LENGTH] = {0};
    /* cal value z */
    sk_sm3_z(id, idlen, px, pxlen, py, pylen, z);

    buflen = msglen + sizeof(z);
    buf = calloc(1, buflen);
    if (buf == NULL)
        return -1;
    /* make value */
    memcpy(buf, z, sizeof(z));
    memcpy(buf + sizeof(z), msg, msglen);
    SM3(buf, buflen, e);
    free(buf);
    return 0;
}

int sk_sm2_keygen(unsigned char *px, int *pxlen,
                  unsigned char *py, int *pylen,
                  unsigned char *prikey, int *prilen)
{
    int ret = -1;
    BN_CTX   *ctx   = NULL;
    EC_KEY   *eckey = NULL;         /* Curve Info */
    const EC_GROUP *group  = NULL;
    const BIGNUM   *bd     = NULL;  /* BigNum Private Key */
    const EC_POINT *pointP = NULL;  /* Public Key Point */
    BIGNUM *bx  = NULL;
    BIGNUM *by  = NULL;

    if (!(ctx = BN_CTX_new()))
        goto err;
    BN_CTX_start(ctx);
    if (!(bx = BN_CTX_get(ctx)))
        goto err;
    if (!(by = BN_CTX_get(ctx)))
        goto err;
    if (!(eckey = EC_KEY_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(group = EC_KEY_get0_group(eckey)))
        goto err;

    /* generate sm2 key */
    ret = EC_KEY_generate_key(eckey);
    if (ret != 1)
        goto err;

    /* ec private key */
    if (!(bd = EC_KEY_get0_private_key(eckey)))
        goto err;
    *prilen = BN_bn2bin(bd, prikey);

    /* ec public key */
    if (!(pointP = EC_KEY_get0_public_key(eckey)))
        goto err;
    if (EC_POINT_get_affine_coordinates(group, pointP, bx, by, ctx) != 1)
        goto err;

    *pxlen = BN_bn2bin(bx, px);
    *pylen = BN_bn2bin(by, py);

    ret = 0;
 err:
    if (ctx)   BN_CTX_end(ctx);
    if (ctx)   BN_CTX_free(ctx);
    if (eckey) EC_KEY_free(eckey);
    return ret;
}

int sk_sm2_point_mul_G(const unsigned char *pe, int pelen,
                       unsigned char *px, int *pxlen,
                       unsigned char *py, int *pylen)
{
    int ret = -1;
    BN_CTX *ctx = NULL;
    BIGNUM *be  = NULL;
    EC_GROUP *group = NULL;        /* Curve Info */
    const EC_POINT *pointG = NULL;

    EC_POINT *point = NULL;        /* Temp Point */
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;


    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;
    BN_CTX_start(ctx);
    if (!(bx = BN_CTX_get(ctx)))
        goto err;
    if (!(by = BN_CTX_get(ctx)))
        goto err;
    if (!(be = BN_CTX_get(ctx)))
        goto err;
    if (!(pointG = EC_GROUP_get0_generator(group)))
        goto err;
    if (!(point = EC_POINT_new(group)))
        goto err;

    // BN Value
    if (!BN_bin2bn(pe, pelen, be))
        goto err;
    // Point mul
    if (EC_POINT_mul(group, point, NULL, pointG, be, ctx) != 1)
        goto err;
    // Get Point
    if (EC_POINT_get_affine_coordinates(group, point, bx, by, ctx) != 1)
        goto err;
    *pxlen = BN_bn2bin(bx, (unsigned char *) px);
    *pylen = BN_bn2bin(by, (unsigned char *) py);

    ret = 0;
err:
    if (ctx)   BN_CTX_end(ctx);
    if (ctx)   BN_CTX_free(ctx);
    if (point) EC_POINT_free(point);
    if (group) EC_GROUP_free(group);
    return ret;
}

int sk_sm2_sign(const unsigned char *hash, int hashlen,
                const unsigned char *d, int dlen,
                unsigned char *cr, int *rlen,
                unsigned char *cs, int *slen)
{
    int ret = -1;
    BN_CTX *ctx     = NULL;
    EC_KEY *eckey    = NULL;       /* Curve Info */
    const EC_POINT *pointG = NULL;
    const EC_GROUP *group  = NULL;
    BIGNUM *be       = NULL;       /* BigNum hash */
    BIGNUM *bk       = NULL;       /* BigNum Rand */
    BIGNUM *bd       = NULL;       /* Private Key */

    EC_POINT *pointX = NULL;       /* Point x value */
    BIGNUM *bx1      = NULL;
    BIGNUM *by1      = NULL;

    const BIGNUM *order = NULL;    /* N value */
    BIGNUM *bn       = NULL;
    BIGNUM *br       = NULL;       /* Sign BigNum r and s */
    BIGNUM *bs       = NULL;

    if (!(eckey = EC_KEY_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(group = EC_KEY_get0_group(eckey)))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;
    BN_CTX_start(ctx);
    if (!(be = BN_CTX_get(ctx)))
        goto err;
    if (!(bk = BN_CTX_get(ctx)))
        goto err;
    if (!(bd = BN_CTX_get(ctx)))
        goto err;
    if (!(bx1 = BN_CTX_get(ctx)))
        goto err;
    if (!(by1 = BN_CTX_get(ctx)))
        goto err;
    if (!(br = BN_CTX_get(ctx)))
        goto err;
    if (!(bs = BN_CTX_get(ctx)))
        goto err;
    if (!(bn = BN_CTX_get(ctx)))
        goto err;

    if (!(pointX = EC_POINT_new(group)))
        goto err;
    if (!(pointG = EC_GROUP_get0_generator(group)))
        goto err;

    if (!BN_bin2bn(d, dlen, bd))
        goto err;

    /* cal e value */
    if (!(BN_bin2bn(hash, hashlen, be)))
        goto err;

    /* get n from eckey */
    if (!(order = EC_GROUP_get0_order(group)))
        goto err;

    /* cal br bs */
    do {
        /* rand k in [1, n-1] */
        do {
            BN_rand_range(bk, order);
        } while (BN_is_zero(bk));

        /* curve point (x1,y1)=[k]G */
        if (EC_POINT_mul(group, pointX, NULL, pointG, bk, ctx) != 1)
            goto err;
        if (EC_POINT_get_affine_coordinates(group, pointX, bx1, by1, ctx) != 1)
            goto err;

        /* r = ( e + x1 ) mod n */
        /* if r = 0 or r + k = n rebuild rand */
        if (BN_mod_add(br, be, bx1, order, ctx) != 1)
            goto err;
        if (BN_mod_add(bn, br, bk, order, ctx) != 1)
            goto err;
        if (BN_is_zero(br) || BN_is_zero(bn))
            continue;

        /* s = ((1 + d)^-1 * (k - rd)) mod n */
        if (!BN_one(bn))
            goto err;
        if (!BN_mod_add(bs, bd, bn, order, ctx))
            goto err;
        if (!BN_mod_inverse(bs, bs, order, ctx))
            goto err;
        if (!BN_mod_mul(bn, br, bd, order, ctx))
            goto err;
        if (!BN_mod_sub(bn, bk, bn, order, ctx))
            goto err;
        if (!BN_mod_mul(bs, bs, bn, order, ctx))
            goto err;
        if (BN_is_zero(bs))
            continue;
        else
            break;
    } while (1);

    /* parse ecdas_sig r and s */
    *rlen = BN_bn2bin(br, cr);
    *slen = BN_bn2bin(bs, cs);

    ret = 0;
err:
    if (ctx)    BN_CTX_end(ctx);
    if (ctx)    BN_CTX_free(ctx);
    if (eckey)  EC_KEY_free(eckey);
    if (pointX) EC_POINT_free(pointX);
    return ret;
}

int sk_sm2_verify(const unsigned char *hash, int hashlen,
                  const unsigned char *cr,   int rlen,
                  const unsigned char *cs,   int slen,
                  const unsigned char *px,   int pxlen,
                  const unsigned char *py,   int pylen)
{
    int ret = -1;
    BN_CTX *ctx   = NULL;

    EC_KEY *eckey = NULL;     /* Curve Info */
    BIGNUM *bx    = NULL;     /* Public Key */
    BIGNUM *by    = NULL;

    ECDSA_SIG *sig = NULL;    /* ECDSA Sign */
    BIGNUM *br     = NULL;
    BIGNUM *bs     = NULL;

    const EC_GROUP *group = NULL;
    const EC_POINT *pub_key = NULL;
    EC_POINT *point = NULL;
    const BIGNUM *order = NULL;
    BIGNUM *e = NULL;
    BIGNUM *t = NULL;

    if (!(ctx = BN_CTX_new()))
        goto err;
    if (!(br = BN_new()))
        goto err;
    if (!(bs = BN_new()))
        goto err;
    BN_CTX_start(ctx);
    if (!(bx = BN_CTX_get(ctx)))
        goto err;
    if (!(by = BN_CTX_get(ctx)))
        goto err;
    if (!(e = BN_CTX_get(ctx)))
        goto err;
    if (!(t = BN_CTX_get(ctx)))
        goto err;
    if (!(eckey = EC_KEY_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(sig = ECDSA_SIG_new()))
        goto err;

    if (!BN_bin2bn(px, pxlen, bx) ||
        !BN_bin2bn(py, pylen, by) ||
        !BN_bin2bn(cr, rlen, br) ||
        !BN_bin2bn(cs, slen, bs))
        goto err;

    /* set public key to eckey */
    if (EC_KEY_set_public_key_affine_coordinates(eckey, bx, by) != 1)
        goto err;

    if (ECDSA_SIG_set0(sig, br, bs) != 1)
        goto err;

    if (!(group = EC_KEY_get0_group(eckey)) ||
        !(pub_key  = EC_KEY_get0_public_key(eckey)))
        goto err;

    if (!(order = EC_GROUP_get0_order(group)))
        goto err;

    /* check r, s in [1, n-1] and r + s != 0 (mod n) */
    if (BN_is_zero(ECDSA_SIG_get0_r(sig)) ||
        BN_is_negative(ECDSA_SIG_get0_r(sig)) ||
        BN_ucmp(ECDSA_SIG_get0_r(sig), order) >= 0 ||
        BN_is_zero(ECDSA_SIG_get0_s(sig)) ||
        BN_is_negative(ECDSA_SIG_get0_s(sig)) ||
        BN_ucmp(ECDSA_SIG_get0_s(sig), order) >= 0)
        goto err;

    /* check t = r + s != 0 */
    if (!BN_mod_add(t, ECDSA_SIG_get0_r(sig), ECDSA_SIG_get0_s(sig), order, ctx))
        goto err;

    if (BN_is_zero(t))
        goto err;

    /* convert digest to e */
    if (!BN_bin2bn(hash, hashlen, e)) {
        goto err;
    }

    /* compute (x, y) = sG + tP, P is pub_key */
    if (!(point = EC_POINT_new(group)))
        goto err;
    if (!EC_POINT_mul(group, point, ECDSA_SIG_get0_s(sig), pub_key, t, ctx))
        goto err;
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(group, point, t, NULL, ctx)) {
            goto err;
        }
    } else /* NID_X9_62_characteristic_two_field */ {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, point, t, NULL, ctx)) {
            goto err;
        }
    }
    if (!BN_nnmod(t, t, order, ctx))
        goto err;

    /* check (sG + tP).x + e  == sig.r */
    if (!BN_mod_add(t, t, e, order, ctx))
        goto err;

    if (BN_ucmp(t, ECDSA_SIG_get0_r(sig)) == 0) {
        ret = 0;
    } else {
        ret = -1;
    }

err:
    if (ctx)   BN_CTX_end(ctx);
    if (ctx)   BN_CTX_free(ctx);
    if (sig)   ECDSA_SIG_free(sig);
    if (eckey) EC_KEY_free(eckey);
    if (point) EC_POINT_free(point);
    return ret;
}

int sk_sm2_encrypt(unsigned char *msg, int msglen,
                   unsigned char *wx,  int wxlen,
                   unsigned char *wy,  int wylen,
                   unsigned char *out, int *outlen) {
    int ret = -1, i = 0;
    int loc2 = 0, loc3 = 0;     /* location c2, location c3 */
    size_t len;
    unsigned char *x2_m_y2 = NULL;
    EC_GROUP *group  = NULL;        /* Curve Info */
    const EC_POINT *pointG  = NULL;
    EC_POINT *point   = NULL;       /* temp point */
    EC_POINT *pointP  = NULL;       /* public key */
    BN_CTX *ctx = NULL;
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    BIGNUM *bn = NULL;
    BIGNUM *bh = NULL;
    BIGNUM *bk = NULL;
    static unsigned char c1[65] = {0};
    static unsigned char buf[65] = {0};

    if (!(x2_m_y2 = (unsigned char *)calloc(1, 96 + msglen)))
        goto err;
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(pointG = EC_GROUP_get0_generator(group)))
        goto err;
    if (!(point = EC_POINT_new(group)))
        goto err;
    if (!(pointP = EC_POINT_new(group)))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;
    BN_CTX_start(ctx);
    if (!(bx = BN_CTX_get(ctx)))
        goto err;
    if (!(by = BN_CTX_get(ctx)))
        goto err;
    if (!(bn = BN_CTX_get(ctx)))
        goto err;
    if (!(bh = BN_CTX_get(ctx)))
        goto err;
    if (!(bk = BN_CTX_get(ctx)))
        goto err;

    /* init ec domain parameters */
    if (!EC_GROUP_get_order(group, bn, ctx)) {
        goto err;
    }
    if (!EC_GROUP_get_cofactor(group, bh, ctx))
        goto err;

    /* set public key point */
    if (!BN_bin2bn(wx, wxlen, bx) ||
        !BN_bin2bn(wy, wylen, by))
        goto err;
    if (EC_POINT_set_affine_coordinates_GFp(group, pointP, bx, by, ctx) != 1)
        goto err;
    if (EC_POINT_is_at_infinity(group, pointP))
        goto err;

    do {
        /* rand k in [1, n-1] */
        do {
            BN_rand_range(bk, bn);
        } while (BN_is_zero(bk));

        /* C1 = [k]G = (x1, y1) */
        if (!EC_POINT_mul(group, point, bn, pointG, bk, ctx))
            goto err;
        if (!(EC_POINT_point2oct(group, point,
                POINT_CONVERSION_UNCOMPRESSED, c1, sizeof(c1), ctx)))
            goto err;

        /* check [h]P_B != O */
        if (!EC_POINT_mul(group, point, NULL, pointP, bh, ctx))
            goto err;
        if (EC_POINT_is_at_infinity(group, point))
            goto err;

        /* compute ECDH [k]P_B = (x2, y2) */
        if (!EC_POINT_mul(group, point, NULL, pointP, bk, ctx))
            goto err;
        if (!(len = EC_POINT_point2oct(group, point,
                POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), ctx)))
            goto err;

        /* compute t = KDF(x2 || y2, clen) */
        if (x963_kdf_sm3(buf + 1, msglen, x2_m_y2) == 0)
            continue;
        break;
    } while (1);

#if C1C3C2
    loc2 = 64 + msglen;
    loc3 = 64;
#else
    loc2 = 64;
    loc3 = 64 + msglen;
#endif
    /* C1 */
    memcpy(out, c1 + 1, len - 1);

    /* C2 */
    memcpy(out + loc2, x2_m_y2, msglen);
    for (i = 0; i < msglen; i++) {
        out[loc2 + i] ^= msg[i];  //C2 = M ⊕t
    }

    /* C3 */
    memcpy(x2_m_y2, buf + 1, 32);
    memcpy(x2_m_y2 + 32, msg, msglen);
    memcpy(x2_m_y2 + 32 + msglen, buf + 1 + 32, 32);
    SM3(x2_m_y2, 64 + msglen, &out[loc3]);

    /* msg length */
    *outlen = 64 + msglen + 32;

    ret = *outlen;
err:
    if (x2_m_y2) free(x2_m_y2);
    
    if (point)  EC_POINT_free(point);
    if (pointP) EC_POINT_free(pointP);
    if (group)  EC_GROUP_free(group);
    if (ctx)    BN_CTX_end(ctx);
    if (ctx)    BN_CTX_free(ctx);
    return ret;
}

int sk_sm2_decrypt(unsigned char *msg, int msglen,
                   unsigned char *d,   int dlen,
                   unsigned char *out, int *outlen)
{
    int ret = -1;
    int loc2 = 0, loc3 = 0, i = 0, ciplen = 0;
    BN_CTX *ctx = NULL;

    EC_GROUP *group = NULL;   /* Curve Info */
    EC_POINT *point = NULL;

    EC_POINT *pointC1 = NULL; /* C1 Info */
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;

    BIGNUM *bd = NULL;        /* Private Key */
    BIGNUM *bn = NULL;
    BIGNUM *bh = NULL;

    unsigned char hash[EVP_MAX_BLOCK_LENGTH];
    unsigned char *x2_m_y2 = NULL;
    unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7) / 4 + 1];

    if (!(ctx = BN_CTX_new()))
        goto err;
    BN_CTX_start(ctx);
    if (!(bx = BN_CTX_get(ctx)))
        goto err;
    if (!(by = BN_CTX_get(ctx)))
        goto err;
    if (!(bd = BN_CTX_get(ctx)))
        goto err;
    if (!(bn = BN_CTX_get(ctx)))
        goto err;
    if (!(bh = BN_CTX_get(ctx)))
        goto err;

    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(pointC1 = EC_POINT_new(group)))
        goto err;
    if (!(point = EC_POINT_new(group)))
        goto err;
    if (!(x2_m_y2 = calloc(1, msglen)))
        goto err;

    /* the cipher data must be greater than 96 */
    if (msglen < 96)
        goto err;
    ciplen = msglen - 96;

    if (!(BN_bin2bn(msg, 32, bx)) ||
        !(BN_bin2bn(msg + 32, 32, by)) ||
        !(BN_bin2bn(d, dlen, bd)))
        goto err;

    /* init ec domain parameters */
    if (!EC_GROUP_get_order(group, bn, ctx)) {
        goto err;
    }
    if (!EC_GROUP_get_cofactor(group, bh, ctx))
        goto err;

    /* verify the C1 (x, y) is or isn't on the curve */
    if (EC_POINT_set_affine_coordinates(group, pointC1, bx, by, ctx) != 1)
        goto err;

    if (EC_POINT_is_at_infinity(group, pointC1) != 0) {
        goto err;
    }

    /* check [h]C1 != O */
    if (!EC_POINT_mul(group, point, NULL, pointC1, bh, ctx))
        goto err;
    if (EC_POINT_is_at_infinity(group, point))
        goto err;

    /* compute ECDH [d]C1 = (x2, y2) */
    if (!EC_POINT_mul(group, point, NULL, pointC1, bd, ctx))
        goto err;
    if (!(EC_POINT_point2oct(group, point,POINT_CONVERSION_UNCOMPRESSED,
            buf, sizeof(buf), ctx)))
        goto err;

    /* compute t = KDF(x2 || y2, clen) */
    if (x963_kdf_sm3(buf + 1, ciplen, out) == 0)
        goto err;

#if C1C3C2
    loc2 = 64 + ciplen;
    loc3 = 64;
#else
    loc2 = 64;
    loc3 = 64 + ciplen;
#endif
    /* Judge C2 */
    for (i = 0; i < ciplen; i++) {
        out[i] ^= msg[i + loc2];
    }
    *outlen = ciplen;

    /* C3 = HASH(x2 | M | y2) */
    memcpy(x2_m_y2, buf + 1, 32);
    memcpy(x2_m_y2 + 32, out, ciplen);
    memcpy(x2_m_y2 + 32 + ciplen, buf + 1 + 32, 32);
    SM3(x2_m_y2, 64 + ciplen, hash);

    /* judge sm3 */
    if (memcmp(hash, msg + loc3, 32) != 0)
        goto err;
    ret = ciplen;
err:
    if (ctx)     BN_CTX_end(ctx);
    if (ctx)     BN_CTX_free(ctx);
    if (group)   EC_GROUP_free(group);
    if (pointC1) EC_POINT_free(pointC1);
    if (point)   EC_POINT_free(point);
    if (x2_m_y2) free(x2_m_y2);
    return ret;
}

int sk_decode_coordinate_y(unsigned char xONE[32], unsigned char yONE[32], unsigned char type)
{
    int ret = -1;
    BIGNUM *bx = NULL;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *point = NULL;
    unsigned char xy[65];

    if (!(bx = BN_new()))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(point = EC_POINT_new(group)))
        goto err;

    /* cover x to bx */
    if (!BN_bin2bn(xONE, 32, bx))
        goto err;
    if (EC_POINT_set_compressed_coordinates_GFp(group, point, bx, type, NULL) != 1)
        goto err;

    // calculate y
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, xy, 65, NULL);
    memcpy(yONE, xy + 33, 32);

    ret = 0;
    err:
    if (bx) BN_free(bx);
    if (ctx) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    if (point) EC_POINT_free(point);
    return ret;
}
