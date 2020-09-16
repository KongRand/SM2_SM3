//
// Created by iwall on 2020/9/14.
//

#include "../include/sk_sm3.h"
#include <openssl/evp.h>

int SM3(const unsigned char *data, size_t len, unsigned char digest[SM3_DIGEST_LENGTH])
{
    const EVP_MD *md;
    EVP_MD_CTX *ctx = NULL;
    if (!(ctx = EVP_MD_CTX_new()))
        return 0;
    md = EVP_sm3();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, digest, NULL);
    EVP_MD_CTX_free(ctx);
    return 1;
}
