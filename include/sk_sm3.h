//
// Created by iwall on 2020/9/14.
//

#ifndef IWALL_V2X_SK_SM3_H
#define IWALL_V2X_SK_SM3_H

#include <stddef.h>

#ifndef SM3_DIGEST_LENGTH
#define SM3_DIGEST_LENGTH 32
#endif

#ifdef __cplusplus
extern "C" {
#endif

int SM3(const unsigned char *data, size_t len, unsigned char digest[SM3_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif //IWALL_V2X_SK_SM3_H
