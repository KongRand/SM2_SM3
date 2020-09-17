//
// Created by iwall on 2020/9/9.
//

#ifndef IWALL_V2X_SK_SM2_H
#define IWALL_V2X_SK_SM2_H

#include <openssl/ec.h>

#ifdef __cplusplus
extern "C" {
#endif

int sk_sm2_keygen(unsigned char *px,     int *pxlen,
                  unsigned char *py,     int *pylen,
                  unsigned char *prikey, int *prilen);

int sk_sm3_z(const unsigned char *id, int idlen,
             const unsigned char *px, int pxlen,
             const unsigned char *py, int pylen,
             unsigned char *z);

int sk_sm3_e(const unsigned char *id,  int idlen,
             const unsigned char *px,  int pxlen,
             const unsigned char *py,  int pylen,
             const unsigned char *msg, int msglen,
             unsigned char *e);

int sk_sm2_point_mul_G(const unsigned char *pe, int pelen,
                       unsigned char *px,       int *pxlen,
                       unsigned char *py,       int *pylen);


int sk_sm2_sign(const unsigned char *hash,   int hashlen,
                const unsigned char *d, int dlen,
                unsigned char *cr, int *rlen,
                unsigned char *cs, int *slen);

int sk_sm2_verify(const unsigned char *hash, int hashlen,
                  const unsigned char *cr,   int rlen,
                  const unsigned char *cs,   int slen,
                  const unsigned char *px,   int pxlen,
                  const unsigned char *py,   int pylen);

int sk_sm2_encrypt(unsigned char *msg, int msglen,
                   unsigned char *wx,  int wxlen,
                   unsigned char *wy,  int wylen,
                   unsigned char *out, int *outlen);

int sk_sm2_decrypt(unsigned char *msg, int msglen,
                   unsigned char *d,   int dlen,
                   unsigned char *out, int *outlen);

int sk_decode_coordinate_y(unsigned char xONE[32], unsigned char yONE[32], unsigned char type);

#ifdef __cplusplus
}
#endif

#endif //IWALL_V2X_SK_SM2_H
