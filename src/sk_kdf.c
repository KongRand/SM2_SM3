//
// Created by iwall on 2020/9/14.
//

#include "../include/sk_kdf.h"
#include "../include/sk_sm3.h"

void *x963_kdf_sm3(const void *in, size_t inlen,
                   unsigned char *out)
{
    unsigned char buf[70] = {0};
    unsigned char digest[32] = {0};
    unsigned int ct = 0x00000001;
    int i, m, n;
    unsigned char *p;

    memcpy(buf, in, 64);
    m = inlen / 32;
    n = inlen % 32;
    p = out;

    for (i = 0; i < m; i++) {
        buf[64] = (ct >> 24) & 0xFF;
        buf[65] = (ct >> 16) & 0xFF;
        buf[66] = (ct >> 8) & 0xFF;
        buf[67] = ct & 0xFF;
        SM3(buf, 68, p);
        p += 32;
        ct++;
    }

    if (n != 0) {
        buf[64] = (ct >> 24) & 0xFF;
        buf[65] = (ct >> 16) & 0xFF;
        buf[66] = (ct >> 8) & 0xFF;
        buf[67] = ct & 0xFF;
        SM3(buf, 68, digest);
    }

    memcpy(p, digest, n);

    for (i = 0; i < inlen; i++) {
        if (out[i] != 0)
            break;
    }
    if (i < inlen)
        return 1;
    else
        return 0;
}
