//
// Created by iwall on 2020/9/14.
//

#ifndef IWALL_V2X_SK_KDF_H
#define IWALL_V2X_SK_KDF_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

void *x963_kdf_sm3(const void *in, size_t inlen,
                   unsigned char *out);

#ifdef __cplusplus
};
#endif


#endif //IWALL_V2X_SK_KDF_H
