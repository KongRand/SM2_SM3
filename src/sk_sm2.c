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



EC_GROUP *new_ec_group(int is_prime_field,
                       const char *p_hex, const char *a_hex, const char *b_hex,
                       const char *x_hex, const char *y_hex, const char *n_hex, const char *h_hex)
{
    int ok = 0;
    EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *n = NULL;
    BIGNUM *h = NULL;
    EC_POINT *G = NULL;
    point_conversion_form_t form = SM2_DEFAULT_POINT_CONVERSION_FORM;
    int flag = 0;

    if (!(ctx = BN_CTX_new()))
        goto err;

    p = BN_new();
    a = BN_new();
    b = BN_new();
    x = BN_new();
    y = BN_new();
    n = BN_new();
    h = BN_new();

    if (!BN_hex2bn(&p, p_hex) ||
        !BN_hex2bn(&a, a_hex) ||
        !BN_hex2bn(&b, b_hex) ||
        !BN_hex2bn(&x, x_hex) ||
        !BN_hex2bn(&y, y_hex) ||
        !BN_hex2bn(&n, n_hex) ||
        !BN_hex2bn(&h, h_hex)) {
        goto err;
    }

    if (is_prime_field) {
        if (!(group = EC_GROUP_new_curve_GFp(p, a, b, ctx))) {
            goto err;
        }
        if (!(G = EC_POINT_new(group))) {
            goto err;
        }
        if (!EC_POINT_set_affine_coordinates_GFp(group, G, x, y, ctx)) {
            goto err;
        }
    }
    else {
        if (!(group = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) {
            goto err;
        }
        if (!(G = EC_POINT_new(group))) {
            goto err;
        }
        if (!EC_POINT_set_affine_coordinates_GF2m(group, G, x, y, ctx)) {
            goto err;
        }
    }

    if (!EC_GROUP_set_generator(group, G, n, h)) {
        goto err;
    }

    EC_GROUP_set_asn1_flag(group, flag);
    EC_GROUP_set_point_conversion_form(group, form);

    ok = 1;
err:
    if (ctx) BN_CTX_free(ctx);
    if (p) BN_free(p);
    if (a) BN_free(a);
    if (b) BN_free(b);
    if (x) BN_free(x);
    if (y) BN_free(y);
    if (n) BN_free(n);
    if (h) BN_free(h);
    if (G) EC_POINT_free(G);
    if (!ok && group) {
        EC_GROUP_free(group);
        group = NULL;
    }
    return group;
}

EC_GROUP *sm2P256_group()
{
    return new_ec_group(1,
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
                        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
                        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                        "1");
}

EC_POINT *sm2G_point(int is_prime_field, const EC_GROUP *group)
{
    char *hx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
    char *hy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
    EC_POINT *pointG = NULL;
    BN_CTX   *ctx    = NULL;
    BIGNUM   *bx     = NULL;
    BIGNUM   *by     = NULL;

    if (!group)
        goto err;
    if (!(pointG = EC_POINT_new(group)))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!BN_hex2bn(&bx, hx) ||
        !BN_hex2bn(&by, hy))
        goto err;

    if (is_prime_field) {
        if (!EC_POINT_set_affine_coordinates_GFp(group, pointG, bx, by, ctx))
            goto err;
    }
    else {
        if (!EC_POINT_set_affine_coordinates_GF2m(group, pointG, bx, by, ctx))
            goto err;
    }
err:
    if (bx)   BN_free(bx);
    if (by)   BN_free(by);
    if (ctx)  BN_CTX_free(ctx);
    return pointG;
}

int sk_sm2_keygen(unsigned char *px, int *pxlen,
                  unsigned char *py, int *pylen,
                  unsigned char *prikey, int *prilen)
{
    int ret = -1;
    const BIGNUM   *bn;
    const EC_POINT *ecpoint;
    BIGNUM   *bx    = NULL;
    BIGNUM   *by    = NULL;
    BN_CTX   *ctx   = NULL;
    EC_KEY   *eckey = NULL;
    EC_GROUP *group = NULL;

    if (!(bx = BN_new()))
        goto err;
    if (!(by = BN_new()))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(eckey = EC_KEY_new()))
        goto err;

    /* generate sm2 key */
    ret = EC_KEY_set_group(eckey, group);
    if (ret != 1)
        goto err;

    ret = EC_KEY_generate_key(eckey);
    if (ret != 1)
        goto err;

    /* ec private key */
    if (!(bn = EC_KEY_get0_private_key(eckey)))
        goto err;
    *prilen = BN_bn2bin(bn, prikey);

    /* ec public key */
    if (!(ecpoint = EC_KEY_get0_public_key(eckey)))
        goto err;
    ret = EC_POINT_get_affine_coordinates(group, ecpoint, bx, by, ctx);
    *pxlen = BN_bn2bin(bx, px);
    *pylen = BN_bn2bin(by, py);
    ret = 0;
err:
    if (bx)    BN_free(bx);
    if (by)    BN_free(by);
    if (ctx)   BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    if (eckey) EC_KEY_free(eckey);
    return ret;
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

int sk_sm2_point_mul_G(const unsigned char *pe, int pelen,
                       unsigned char *px, int *pxlen,
                       unsigned char *py, int *pylen)
{
    int ret = -1;
    BIGNUM *bx = NULL, *by = NULL, *be = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *pointG = NULL;
    BN_CTX *ctx = NULL;

    if (!(bx = BN_new()))
        goto err;
    if (!(by = BN_new()))
        goto err;
    if (!(be = BN_new()))
        goto err;
    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;
    if (!(pointG = sm2G_point(1, group)))
        goto err;

    // BN Value
    if (!BN_bin2bn(pe, pelen, be))
        goto err;

    // Point mul
    if (EC_POINT_mul(group, pointG, NULL, pointG, be, ctx) != 1)
        goto err;

    // Get Point
    if (EC_POINT_get_affine_coordinates(group, pointG, bx, by, ctx) != 1)
        goto err;

    *pxlen = BN_bn2bin(bx, (unsigned char *) px);
    *pylen = BN_bn2bin(by, (unsigned char *) py);

    ret = 0;
err:
    if(bx) BN_free(bx);
    if(by) BN_free(by);
    if(be) BN_free(be);
    if(group) EC_GROUP_free((EC_GROUP *)group);
    if(pointG) EC_POINT_free(pointG);
    if(ctx) BN_CTX_free(ctx);
    return ret;
}

int sk_sm2_sign(const unsigned char *hash, int hashlen,
                const unsigned char *d, int dlen,
                unsigned char *cr, int *rlen,
                unsigned char *cs, int *slen)
{
    int ret = -1;
    BIGNUM *be      = NULL;
    BIGNUM *bk      = NULL;
    BIGNUM *order   = NULL;
    BIGNUM *bd      = NULL;
    BIGNUM *bx1 = NULL, *by1 = NULL;
    BIGNUM *br = NULL, *bs = NULL, *bn = NULL;    /* sign br bs */

    EC_KEY *eckey   = NULL;
    BN_CTX *ctx     = NULL;
    EC_POINT *pointX = NULL;
    EC_POINT *pointG = NULL;
    const EC_GROUP *group = NULL;

    if (!(be = BN_new()))
        goto err;
    if (!(bk = BN_new()))
        goto err;
    if (!(order = BN_new()))
        goto err;
    if (!(bd = BN_new()))
        goto err;
    if (!(bx1 = BN_new()))
        goto err;
    if (!(by1 = BN_new()))
        goto err;
    if (!(br = BN_new()))
        goto err;
    if (!(bs = BN_new()))
        goto err;
    if (!(bn = BN_new()))
        goto err;
    if (!(eckey = EC_KEY_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(group = EC_KEY_get0_group(eckey)))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;

    if (!(pointX = EC_POINT_new(group)))
        goto err;
    if (!(pointG = sm2G_point(1, group)))
        goto err;

    if (!BN_bin2bn(d, dlen, bd))
        goto err;

    /* cal e value */
    if (!(BN_bin2bn(hash, hashlen, be)))
        goto err;

    /* get n from eckey */
    if (EC_GROUP_get_order(group, order, ctx) != 1)
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
    if (be)  BN_free(be);
    if (bk)  BN_free(bk);
    if (order) BN_free(order);
    if (bd)  BN_free(bd);
    if (bn)  BN_free(bn);
    if (br)  BN_free(br);
    if (bs)  BN_free(bs);
    if (bx1)  BN_free(bx1);
    if (by1)  BN_free(by1);
    if (eckey) EC_KEY_free(eckey);
    if (ctx) BN_CTX_free(ctx);
    if (pointX) EC_POINT_free(pointX);
    if (pointG) EC_POINT_free(pointG);
    return ret;
}

int sk_sm2_verify(const unsigned char *hash, int hashlen,
                  const unsigned char *cr,   int rlen,
                  const unsigned char *cs,   int slen,
                  const unsigned char *px,   int pxlen,
                  const unsigned char *py,   int pylen)
{
    int ret = -1;
    int i   = 0;
    BIGNUM *bx    = NULL;
    BIGNUM *by    = NULL;
    BIGNUM *br    = NULL;
    BIGNUM *bs    = NULL;
    EC_KEY *eckey = NULL;
    ECDSA_SIG *sig = NULL;

    const EC_GROUP *ec_group = NULL;
    const EC_POINT *pub_key = NULL;
    EC_POINT *point = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *order = NULL;
    BIGNUM *e = NULL;
    BIGNUM *t = NULL;

    if (!(bx = BN_new()))
        goto err;
    if (!(by = BN_new()))
        goto err;
    if (!(br = BN_new()))
        goto err;
    if (!(bs = BN_new()))
        goto err;
    if (!(ctx = BN_CTX_new()))
        goto err;
    if (!(order = BN_new()))
        goto err;
    if (!(e = BN_new()))
        goto err;
    if (!(t = BN_new()))
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

    if (!(ec_group = EC_KEY_get0_group(eckey)) ||
        !(pub_key  = EC_KEY_get0_public_key(eckey))) {
        return -1;
    }

    if (!EC_GROUP_get_order(ec_group, order, ctx)) {
        goto err;
    }

    /* check r, s in [1, n-1] and r + s != 0 (mod n) */
    if (BN_is_zero(ECDSA_SIG_get0_r(sig)) ||
        BN_is_negative(ECDSA_SIG_get0_r(sig)) ||
        BN_ucmp(ECDSA_SIG_get0_r(sig), order) >= 0 ||
        BN_is_zero(ECDSA_SIG_get0_s(sig)) ||
        BN_is_negative(ECDSA_SIG_get0_s(sig)) ||
        BN_ucmp(ECDSA_SIG_get0_s(sig), order) >= 0) {
        ret = -1;
        goto err;
    }

    /* check t = r + s != 0 */
    if (!BN_mod_add(t, ECDSA_SIG_get0_r(sig), ECDSA_SIG_get0_s(sig), order, ctx)) {
        goto err;
    }
    if (BN_is_zero(t)) {
        ret = 0;
        goto err;
    }

    /* convert digest to e */
    i = BN_num_bits(order);

    if (!BN_bin2bn(hash, hashlen, e)) {
        goto err;
    }

    /* compute (x, y) = sG + tP, P is pub_key */
    if (!(point = EC_POINT_new(ec_group))) {
        goto err;
    }
    if (!EC_POINT_mul(ec_group, point, ECDSA_SIG_get0_s(sig), pub_key, t, ctx)) {
        goto err;
    }
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
        if (!EC_POINT_get_affine_coordinates_GFp(ec_group, point, t, NULL, ctx)) {
            goto err;
        }
    } else /* NID_X9_62_characteristic_two_field */ {
        if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, t, NULL, ctx)) {
            goto err;
        }
    }
    if (!BN_nnmod(t, t, order, ctx)) {
        goto err;
    }

    /* check (sG + tP).x + e  == sig.r */
    if (!BN_mod_add(t, t, e, order, ctx)) {
        goto err;
    }

    if (BN_ucmp(t, ECDSA_SIG_get0_r(sig)) == 0) {
        ret = 0;
    } else {
        ret = -1;
    }

err:
    if (bx) BN_free(bx);
    if (by) BN_free(by);
    if (eckey) EC_KEY_free(eckey);
    if (sig) ECDSA_SIG_free(sig);

    if (point) EC_POINT_free(point);
    if (order) BN_free(order);
    if (e) BN_free(e);
    if (t) BN_free(t);
    if (ctx) BN_CTX_free(ctx);

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
    EC_GROUP *group  = NULL;
    EC_POINT *point   = NULL;   /* temp point */
    EC_POINT *pointG  = NULL;   /* G point */
    EC_POINT *pointP  = NULL;   /* public key */
    BN_CTX *ctx = NULL;
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    BIGNUM *bn = NULL;
    BIGNUM *bh = NULL;
    BIGNUM *bk = NULL;
    static unsigned char c1[65] = {0};
    static unsigned char buf[65] = {0};

    if (!(bx = BN_new()))
        goto err;
    if (!(by = BN_new()))
        goto err;
    if (!(bn = BN_new()))
        goto err;
    if (!(bh = BN_new()))
        goto err;
    if (!(bk = BN_new()))
        goto err;
    if (!(x2_m_y2 = (unsigned char *)calloc(1, 96 + msglen)))
        goto err;

    if (!(group = EC_GROUP_new_by_curve_name(NID_sm2)))
        goto err;
    if (!(point = EC_POINT_new(group)))
        goto err;
    if (!(pointG = sm2G_point(1, group)))
        goto err;
    if (!(pointP = EC_POINT_new(group)))
        goto err;
    if (!(ctx = BN_CTX_new()))
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
        if (!EC_POINT_mul(group, pointG, bn, pointG, bk, ctx))
            goto err;
        if (!(EC_POINT_point2oct(group, pointG,
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

    if (bx) BN_free(bx);
    if (by) BN_free(by);
    if (bn) BN_free(bn);
    if (bh) BN_free(bh);
    if (bk) BN_free(bk);
    if (x2_m_y2) free(x2_m_y2);
    
    if (point)  EC_POINT_free(point);
    if (pointG) EC_POINT_free(pointG);
    if (pointP) EC_POINT_free(pointP);
    if (group)  EC_GROUP_free(group);
    if (ctx)    BN_CTX_free(ctx);
    return ret;
}

int sk_sm2_decrypt(unsigned char *msg, int msglen,
                   unsigned char *d,   int dlen,
                   unsigned char *out, int *outlen)
{
    int ret = -1;
    int loc2 = 0, loc3 = 0, i = 0, ciplen = 0;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BN_CTX *ctx = NULL;

    /* C1 value */
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    EC_POINT *pointC1 = NULL;
    BIGNUM *bd = NULL;
    BIGNUM *bn = NULL;
    BIGNUM *bh = NULL;
    unsigned char hash[EVP_MAX_BLOCK_LENGTH];
    unsigned char *x2_m_y2 = NULL;
    unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7) / 4 + 1];

    if (!(bx = BN_new()))
        goto err;
    if (!(by = BN_new()))
        goto err;
    if (!(bd = BN_new()))
        goto err;
    if (!(bn = BN_new()))
        goto err;
    if (!(bh = BN_new()))
        goto err;
    if (!(ctx = BN_CTX_new()))
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
    if (bx) BN_free(bx);
    if (by) BN_free(by);
    if (bd) BN_free(bd);
    if (bn) BN_free(bn);
    if (bh) BN_free(bh);
    if (ctx) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
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
