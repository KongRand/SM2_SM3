#include <stdio.h>
#include "sk_sm2.h"
void printf_val(unsigned char *p, int plen)
{
    printf("\n");
    for (int i = 0; i < plen; ++i)
    {
        printf("%02x", p[i]);
    }
    printf("\n");
}

void printf_hex_val(unsigned char *p, int plen)
{
    printf("\n");
    for (int i = 0; i < plen; ++i)
    {
        if ((i != 0) && ((i % 8) == 0))
            printf("\n");
        printf("0x%02x, ", p[i]);
    }
    printf("\n");
}

static unsigned char px[32] = {0};
static int pxlen  = 32;
static unsigned char py[32] = {0};
static int pylen  = 32;
static unsigned char pd[32] = {0};
static int pdlen  = 32;

void sm2_key_gen()
{
    int ret = -1;
    ret = sk_sm2_keygen(px, &pxlen, py, &pylen, pd, &pdlen);
    printf("%s line: %d res: %d\n", __func__, __LINE__, ret);

    printf("public key x:");
    printf_hex_val(px, pxlen);

    printf("public key y:");
    printf_hex_val(py, pylen);

    printf("private key d:");
    printf_hex_val(pd, pdlen);
}

unsigned char test_data[128] = {
        0xB3, 0x2D, 0xA9, 0xAA, 0xC2, 0xFE, 0xF6, 0x5A, 0x4A, 0xBC, 0x86, 0x8E, 0x20, 0x8B, 0x04, 0x94,
        0x9E, 0x93, 0xDA, 0x9E, 0x37, 0xC3, 0x4A, 0x77, 0x9E, 0x4E, 0x59, 0xAF, 0x71, 0x8F, 0x18, 0x9B,
        0xB2, 0x48, 0xF3, 0xD0, 0x28, 0x90, 0x43, 0x94, 0x56, 0x8E, 0x03, 0x81, 0xC7, 0x50, 0x93, 0x6E,
        0x2B, 0xC1, 0x7B, 0x39, 0xCA, 0x3E, 0xB3, 0xA1, 0xF3, 0x62, 0x9F, 0x5C, 0x6E, 0x40, 0x4F, 0x36,
        0x92, 0x0A, 0x32, 0xAE, 0x12, 0x4A, 0x01, 0x71, 0x1F, 0x7A, 0xEB, 0x0B, 0x03, 0x7C, 0x93, 0xBA,
        0x97, 0xC6, 0x30, 0x6E, 0x05, 0x3F, 0x79, 0x5A, 0x4B, 0xF0, 0x1B, 0x9F, 0x74, 0x62, 0x24, 0xB5,
        0x4F, 0x51, 0x5B, 0x7F, 0x01, 0xEA, 0x08, 0x95, 0x83, 0xAD, 0x54, 0x18, 0xFF, 0xBE, 0xBF, 0x01,
        0x96, 0x6C, 0x89, 0x81, 0x17, 0x7D, 0x4E, 0x65, 0x8B, 0xE2, 0x29, 0xB6, 0x87, 0x20, 0x26, 0xF6,
};

void sm2_encrypt_decrypt()
{
    int ret = -1;
    unsigned char cipher[256] = {0};
    int cipherlen = 256;
    ret = sk_sm2_encrypt(test_data, sizeof(test_data),
            px, sizeof(px),
            py, sizeof(py),
            cipher, &cipherlen);
    printf("encrypt cipher: ");
    printf_hex_val(cipher, cipherlen);

    unsigned char plain[128] = {0};
    int plainlen = 128;
    ret = sk_sm2_decrypt(cipher, cipherlen, pd, pdlen, plain, &plainlen);
    printf("decrypt plain: ");
    printf_hex_val(plain, plainlen);
}

void sm2_sign_verify()
{
    int ret = -1;
    unsigned char cr[32] = {0};
    int crlen = 32;
    unsigned char cs[32] = {0};
    int cslen = 32;
    unsigned char e[32]  = {0};
    unsigned char gm_id[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    sk_sm3_e(gm_id, sizeof(gm_id), px, pxlen, py, pylen, test_data, sizeof(test_data), e);

    ret = sk_sm2_sign(e, sizeof(e), pd, sizeof(pd), cr, &crlen, cs, &cslen);
    printf("sign r: ");
    printf_hex_val(cr, crlen);

    printf("sign s: ");
    printf_hex_val(cs, cslen);

    ret = sk_sm2_verify(e, sizeof(e), cr, crlen, cs, cslen, px, pxlen, py, pylen);
    printf("%s line: %d res: %d\n", __func__, __LINE__, ret);
}

void sm2_point_mul_G()
{
    int ret = -1;
    unsigned char gx[32] = {0};
    int gxlen = 32;
    unsigned char gy[32] = {0};
    int gylen = 32;
    ret = sk_sm2_point_mul_G(test_data, sizeof(test_data), gx, &gxlen, gy, &gylen);
    printf("sk_sm2_point_mul_G %d\n", ret);
    printf_hex_val(gx, gxlen);
    printf_hex_val(gy, gylen);
}

void sm2_decode_coordinate_y()
{
    unsigned char tpy[32] = {0};
    sk_decode_coordinate_y(px, tpy, 1);
    printf_hex_val(tpy, 32);
}

int main()
{
    printf("Hello, World!\n");

    sm2_key_gen();

    sm2_encrypt_decrypt();

    sm2_sign_verify();

    sm2_point_mul_G();

    sm2_decode_coordinate_y();

    return 0;
}
