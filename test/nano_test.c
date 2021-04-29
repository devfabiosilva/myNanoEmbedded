#include <common_test.h>

void nano_address_test()
{
   int err, i;
   char *dest=msgbuf()+(BUF_MSG_SZ>>1);
   uint8_t *public_key_from_wallet=(uint8_t *)msgbuf()+(BUF_MSG_SZ>>2);
   char *prefixes[]={XRB_PREFIX, NANO_PREFIX}, *p;
   NANO_PUBLIC_KEY_EXTENDED public_key_extended;

   const uint8_t nano_public_key[] = {
      0x21, 0xb1, 0x62, 0x63, 0xac, 0x3f, 0xc0, 0xe3, 0x3f, 0xa6, 0x82, 0xd3, 0xcc, 0x24, 0x13, 0xb9,
      0xb4, 0x0d, 0x03, 0x51, 0xe3, 0x4a, 0xbb, 0x48, 0x58, 0xf5, 0x29, 0x36, 0x71, 0x2e, 0xce, 0x72
   };

   clear_msgbuf();
   for (i=0;i<sizeof(prefixes)/sizeof(prefixes[0]);) {
      err=pk_to_wallet(dest, p=prefixes[i++], memcpy(public_key_extended, nano_public_key, sizeof(nano_public_key)));

      C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
         CTEST_SETTER(
            CTEST_INFO("Parsing Nano public key \"%s\" to Nano address ...", fhex2strv2(msgbuf(), nano_public_key, sizeof(nano_public_key), 1)),
            CTEST_ON_ERROR("It should return ERROR_SUCCESS (%d)", ERROR_SUCCESS),
            CTEST_ON_SUCCESS("Success. \"pk_to_wallet\" Nano wallet = \"%s\" with Nano prefix = \"%s\"", dest, p)
         )
      )

      C_ASSERT_TRUE(is_nano_prefix((const char *)dest, (const char *)p),
         CTEST_SETTER(
            CTEST_INFO("Checking if \"%s\" has prefix \"%s\" ...", dest, p),
            CTEST_ON_ERROR("\"is_nano_prefix\" should return TRUE (%d) for prefix \"%s\" for this wallet: \"%s\"", C_TEST_TRUE, p, dest),
            CTEST_ON_SUCCESS("\"is_nano_prefix\" returned TRUE (%d) for prefix \"%s\" for this wallet: \"%s\"", C_TEST_TRUE, p, dest)
         )
      )

      err=nano_base_32_2_hex(public_key_from_wallet, dest);

      C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
         CTEST_SETTER(
            CTEST_INFO("Checking parsing \"%s\" to public key ...", dest)
         )
      )

      C_ASSERT_EQUAL_BYTE((void *)nano_public_key, public_key_from_wallet, sizeof(nano_public_key),
         CTEST_SETTER(
            CTEST_INFO("Checking if public key of %lu bytes at address (%p) and (%p) are equals", sizeof(nano_public_key), nano_public_key, public_key_from_wallet),
            CTEST_ON_ERROR("Was expected \"%s\" but found \"%s\"", msgbuf(), fhex2strv2(msgbuf()+128, public_key_from_wallet, sizeof(nano_public_key), 1))
         )
      )

   }

}

void nano_seed_test()
{

}

void nano_bip39_test()
{

}

void nano_encrypted_stream_test()
{

}

void nano_p2pow_test()
{

}

void nano_block_test()
{

}
