#ifndef _HASH_FUNC_H
#define _HASH_FUNC_H

#ifdef __cplusplus
extern "C" {
#endif

	
typedef unsigned int u32;

void sha256_transform (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[8]);
void hmac_sha256_pad(u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 T1[8], u32 T2[8]);
void hmac_sha256_run (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 T1[8], u32 T2[8], u32 digest[8]);
void MyHmac(u32 pwd[16],u32 M[16],u32 Result[8]);




#define SHIFT_RIGHT_32(x,n) ((x) >> (n))

#define rotl32(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))

#define SHA256_S0(x) (rotl32 ((x), 25u) ^ rotl32 ((x), 14u) ^ SHIFT_RIGHT_32 ((x),  3u))
#define SHA256_S1(x) (rotl32 ((x), 15u) ^ rotl32 ((x), 13u) ^ SHIFT_RIGHT_32 ((x), 10u))
#define SHA256_S2(x) (rotl32 ((x), 30u) ^ rotl32 ((x), 19u) ^ rotl32 ((x), 10u))
#define SHA256_S3(x) (rotl32 ((x), 26u) ^ rotl32 ((x), 21u) ^ rotl32 ((x),  7u))

#define SHA256_F0(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA256_F1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA256_F0o(x,y,z) (SHA256_F0 ((x), (y), (z)))
#define SHA256_F1o(x,y,z) (SHA256_F1 ((x), (y), (z)))

#define SHA256_STEP_S(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                                 \
  h += K;                                         \
  h += x;                                         \
  h += SHA256_S3_S (e);                           \
  h += F1 (e,f,g);                                \
  d += h;                                         \
  h += SHA256_S2_S (a);                           \
  h += F0 (a,b,c);                                \
}

#define SHA256_EXPAND_S(x,y,z,w) (SHA256_S1_S (x) + y + SHA256_S0_S (z) + w)

#define SHA256_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)    \
{                                                 \
  h += K;                                         \
  h += x;                                         \
  h += SHA256_S3 (e);                             \
  h += F1 (e,f,g);                                \
  d += h;                                         \
  h += SHA256_S2 (a);                             \
  h += F0 (a,b,c);                                \
}

#define SHA256_EXPAND(x,y,z,w) (SHA256_S1 (x) + y + SHA256_S0 (z) + w)

typedef enum sha256_constants
{
  SHA256M_A=0x6a09e667,
  SHA256M_B=0xbb67ae85,
  SHA256M_C=0x3c6ef372,
  SHA256M_D=0xa54ff53a,
  SHA256M_E=0x510e527f,
  SHA256M_F=0x9b05688c,
  SHA256M_G=0x1f83d9ab,
  SHA256M_H=0x5be0cd19,

  SHA256C00=0x428a2f98,
  SHA256C01=0x71374491,
  SHA256C02=0xb5c0fbcf,
  SHA256C03=0xe9b5dba5,
  SHA256C04=0x3956c25b,
  SHA256C05=0x59f111f1,
  SHA256C06=0x923f82a4,
  SHA256C07=0xab1c5ed5,
  SHA256C08=0xd807aa98,
  SHA256C09=0x12835b01,
  SHA256C0a=0x243185be,
  SHA256C0b=0x550c7dc3,
  SHA256C0c=0x72be5d74,
  SHA256C0d=0x80deb1fe,
  SHA256C0e=0x9bdc06a7,
  SHA256C0f=0xc19bf174,
  SHA256C10=0xe49b69c1,
  SHA256C11=0xefbe4786,
  SHA256C12=0x0fc19dc6,
  SHA256C13=0x240ca1cc,
  SHA256C14=0x2de92c6f,
  SHA256C15=0x4a7484aa,
  SHA256C16=0x5cb0a9dc,
  SHA256C17=0x76f988da,
  SHA256C18=0x983e5152,
  SHA256C19=0xa831c66d,
  SHA256C1a=0xb00327c8,
  SHA256C1b=0xbf597fc7,
  SHA256C1c=0xc6e00bf3,
  SHA256C1d=0xd5a79147,
  SHA256C1e=0x06ca6351,
  SHA256C1f=0x14292967,
  SHA256C20=0x27b70a85,
  SHA256C21=0x2e1b2138,
  SHA256C22=0x4d2c6dfc,
  SHA256C23=0x53380d13,
  SHA256C24=0x650a7354,
  SHA256C25=0x766a0abb,
  SHA256C26=0x81c2c92e,
  SHA256C27=0x92722c85,
  SHA256C28=0xa2bfe8a1,
  SHA256C29=0xa81a664b,
  SHA256C2a=0xc24b8b70,
  SHA256C2b=0xc76c51a3,
  SHA256C2c=0xd192e819,
  SHA256C2d=0xd6990624,
  SHA256C2e=0xf40e3585,
  SHA256C2f=0x106aa070,
  SHA256C30=0x19a4c116,
  SHA256C31=0x1e376c08,
  SHA256C32=0x2748774c,
  SHA256C33=0x34b0bcb5,
  SHA256C34=0x391c0cb3,
  SHA256C35=0x4ed8aa4a,
  SHA256C36=0x5b9cca4f,
  SHA256C37=0x682e6ff3,
  SHA256C38=0x748f82ee,
  SHA256C39=0x78a5636f,
  SHA256C3a=0x84c87814,
  SHA256C3b=0x8cc70208,
  SHA256C3c=0x90befffa,
  SHA256C3d=0xa4506ceb,
  SHA256C3e=0xbef9a3f7,
  SHA256C3f=0xc67178f2u

} sha256_constants_t;

#ifdef __cplusplus
}
#endif
#endif

