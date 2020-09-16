# SM2_SM3

本项目依赖 OpenSSL 参考《国密局-SM2椭圆曲线公钥密码算法 第一部分，第二部分，第三部分》
实现 SM2 加解密， SM2 签名验签。


### 生成 SM2 密钥对
```c
int sk_sm2_keygen(unsigned char *px,     int *pxlen,
                  unsigned char *py,     int *pylen,
                  unsigned char *prikey, int *prilen);
```
### 生成 SM3_Z 值 (签名验签使用)
```c
int sk_sm3_z(const unsigned char *id, int idlen,
             const unsigned char *px, int pxlen,
             const unsigned char *py, int pylen,
             unsigned char *z);
```
### 生成 SM3_E 值 (签名验签名使用) 
```c
int sk_sm3_e(const unsigned char *id,  int idlen,
             const unsigned char *px,  int pxlen,
             const unsigned char *py,  int pylen,
             const unsigned char *msg, int msglen,
             unsigned char *e);
```
### 点乘 G 
```c
int sk_sm2_point_mul_G(const unsigned char *pe, int pelen,
                       unsigned char *px,       int *pxlen,
                       unsigned char *py,       int *pylen);
```
### SM2 签名算法
```c
int sk_sm2_sign(const unsigned char *hash,   int hashlen,
                const unsigned char *d, int dlen,
                unsigned char *cr, int *rlen,
                unsigned char *cs, int *slen);
```
### SM2 验签名算法
```c
int sk_sm2_verify(const unsigned char *hash, int hashlen,
                  const unsigned char *cr,   int rlen,
                  const unsigned char *cs,   int slen,
                  const unsigned char *px,   int pxlen,
                  const unsigned char *py,   int pylen);
```
### SM2 加密算法
```c
int sk_sm2_encrypt(unsigned char *msg, int msglen,
                   unsigned char *wx,  int wxlen,
                   unsigned char *wy,  int wylen,
                   unsigned char *out, int *outlen);
```
### SM2 解密算法
```c
int sk_sm2_decrypt(unsigned char *msg, int msglen,
                   unsigned char *d,   int dlen,
                   unsigned char *out, int *outlen);
```
### SM2 曲线点 X 计算 曲线点 Y 
```c
int sk_decode_coordinate_y(unsigned char xONE[32], 
                           unsigned char yONE[32], 
                           unsigned char type);
```

