#include "common_test.h"

static int load_master_prv_key(void *handle, unsigned char *data, size_t data_sz)
{
   if (data_sz!=32)
      return 1;

   memcpy(data, handle, 32);
   return 0;
}

void uncompress_eliptic_curve_test()
{
   int err;
   uint8_t prv_key[] = {0xde, 0x0c, 0x84, 0x21, 0x5a, 0x6b, 0x74, 0x29, 0xd3, 0xd2, 0x83, 0x6f, 0x54, 0xb6, 0xb9,
      0x17, 0xc9, 0x30, 0x11, 0x03, 0x13, 0x49, 0x04, 0x45, 0x7a, 0x92, 0x8c, 0x56, 0x58, 0x0c, 0xf5, 0xa4};
   f_ecdsa_key_pair key_pair_compressed, key_pair_uncompressed;
   char *p=&buf_msg[sizeof(buf_msg)>>1], *q=&buf_msg[sizeof(buf_msg)>>2];
   size_t sz;

   key_pair_compressed.gid=MBEDTLS_ECP_DP_SECP256K1;
   key_pair_compressed.ctx=NULL;

   key_pair_uncompressed.gid=MBEDTLS_ECP_DP_SECP256K1;
   key_pair_uncompressed.ctx=NULL;

   err=f_gen_ecdsa_key_pair(&key_pair_compressed, MBEDTLS_ECP_PF_COMPRESSED, load_master_prv_key, (void *)prv_key);

   C_ASSERT_EQUAL_INT(0, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_gen_ecdsa_key_pair\" generating compressed public key from private key = \"%s\" ...",
            fhex2strv2(buf_msg, prv_key, sizeof(prv_key), 1))
      )
   );

   C_ASSERT_TRUE(key_pair_compressed.public_key_sz>0,
      CTEST_SETTER(
         CTEST_ON_SUCCESS("Compressed key size %u and value \"%s\"",
            key_pair_compressed.public_key_sz, fhex2strv2(buf_msg, key_pair_compressed.public_key, key_pair_compressed.public_key_sz, 1))
      )
   );

   err=f_gen_ecdsa_key_pair(&key_pair_uncompressed, MBEDTLS_ECP_PF_UNCOMPRESSED, load_master_prv_key, (void *)prv_key);

   C_ASSERT_EQUAL_INT(0, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_gen_ecdsa_key_pair\" generating uncompressed public key from private key = \"%s\" ...",
            fhex2strv2(buf_msg, prv_key, sizeof(prv_key), 1))
      )
   );

   C_ASSERT_TRUE(key_pair_uncompressed.public_key_sz>0,
      CTEST_SETTER(
         CTEST_ON_SUCCESS("Uncompressed key size %u and value \"%s\"",
            key_pair_uncompressed.public_key_sz, fhex2strv2(buf_msg, key_pair_uncompressed.public_key, key_pair_uncompressed.public_key_sz, 1))
      )
   );

   err=f_uncompress_elliptic_curve((uint8_t *)p, sizeof(buf_msg)>>1, &sz,
      key_pair_compressed.gid, key_pair_compressed.public_key, key_pair_compressed.public_key_sz);

   C_ASSERT_EQUAL_INT(0, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_uncompress_elliptic_curve\" for uncompressing public key = \"%s\" ...", buf_msg)
      )
   );

   C_ASSERT_EQUAL_BYTE(
      key_pair_uncompressed.public_key,
      p,
      key_pair_uncompressed.public_key_sz,
      CTEST_SETTER(
         CTEST_ON_SUCCESS("Compressed key size %u and value \"%s\"\nValue from \"f_uncompress_elliptic_curve\" => %s",
            key_pair_uncompressed.public_key_sz, buf_msg, fhex2strv2(q, p, key_pair_uncompressed.public_key_sz, 1)
         )
      )
   );

}

