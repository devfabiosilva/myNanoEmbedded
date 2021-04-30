#include <common_test.h>

#define NANO_PREFIX_ERROR_MSG "\"is_nano_prefix\" should return TRUE (%d) for prefix \"%s\" for this wallet: \"%s\""
#define NANO_PREFIX_SUCCESS_MSG "\"is_nano_prefix\" returned TRUE (%d) for prefix \"%s\" for this wallet: \"%s\""
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
            CTEST_ON_ERROR(NANO_PREFIX_ERROR_MSG, C_TEST_TRUE, p, dest),
            CTEST_ON_SUCCESS(NANO_PREFIX_SUCCESS_MSG, C_TEST_TRUE, p, dest)
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

   dest[10]='m';
   err=nano_base_32_2_hex(public_key_from_wallet, dest);

   C_ASSERT_EQUAL_INT(ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM, err,
      CTEST_SETTER(
         CTEST_WARN(
            "Expecting error ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM (%d) from \"nano_base_32_2_hex\" due to invalid wallet address \"%s\"",
            ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM, dest
         ),
         CTEST_ON_ERROR("Was expected ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM (%d) but found (%d)", ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM, err),
         CTEST_ON_SUCCESS("ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM (%d) expected success", ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM)
      )
   )

}

void nano_seed_test()
{
   int i, err;
   uint8_t *seed_tmp=(uint8_t *)msgbuf()+(BUF_MSG_SZ>>2);
   uint8_t *private_key_tmp=seed_tmp+(BUF_MSG_SZ>>2);
   uint8_t *public_key_tmp=private_key_tmp+(BUF_MSG_SZ>>2);
   char *msg1=msgbuf();
#define MSG_SZ 128
   char *msg2=msgbuf()+MSG_SZ;

   struct seed_t {
      const char *seed_name;
      uint8_t nano_seed_test[32];
   } nano_seed = {
      "C7E07195BFAA93A0F7B8A106957C64D4626B10A20B010C5DEA0F68CD9844D034",
      {0xC7, 0xE0, 0x71, 0x95, 0xBF, 0xAA, 0x93, 0xA0, 0xF7, 0xB8, 0xA1, 0x06, 0x95, 0x7C, 0x64, 0xD4,
      0x62, 0x6B, 0x10, 0xA2, 0x0B, 0x01, 0x0C, 0x5D, 0xEA, 0x0F, 0x68, 0xCD, 0x98, 0x44, 0xD0, 0x34}
   };

   struct seed_test_t {
      char *address;
      char *nano_prefix;
      uint32_t wallet_number;
      uint8_t private_key[sizeof(NANO_PRIVATE_KEY)];
      uint8_t public_key[sizeof(NANO_PUBLIC_KEY_EXTENDED)];
   } SEED_TEST[] = {
      {
         "xrb_16hsbha1tixrxyjrrf618qjr31cpwbisa8s4boj9916uj5e6to7oxkizghgc",
         XRB_PREFIX,
         2021,
         {
            0x35, 0x14, 0x41, 0xDE, 0xD4, 0x0C, 0x98, 0xFE, 0xBF, 0x74, 0xAF, 0x5B, 0xFA, 0x03, 0x5B, 0xFF,
            0x9F, 0xD8, 0xAA, 0x64, 0x9E, 0x3A, 0xEF, 0x00, 0x64, 0x2E, 0x33, 0x4F, 0xDD, 0xB2, 0xEA, 0x51
         },
         {
            0x11, 0xF9, 0x4B, 0xD0, 0x0D, 0x43, 0xB8, 0xEF, 0xA3, 0x8C, 0x34, 0x80, 0x35, 0xE3, 0x80, 0x81,
            0x56, 0xE2, 0x61, 0x94, 0x1B, 0x22, 0x4D, 0x62, 0x73, 0x80, 0x9B, 0x88, 0xD8, 0x4D, 0x54, 0xB5
         }
      },
      {
         "nano_3whqqwu9oix8hdkgx3k5megm7i9mymcrxoktmnnsjg5i55zagw7dxqb1i3xs",
         NANO_PREFIX,
         0,
         {
            0x74, 0x80, 0x92, 0x2E, 0x02, 0x64, 0xF9, 0x6B, 0xA0, 0xF0, 0xE8, 0xDA, 0x4C, 0x1F, 0x93, 0xE7,
            0x93, 0xAE, 0x05, 0x73, 0x8C, 0xCE, 0x9D, 0x0F, 0x5C, 0x90, 0xBD, 0x0F, 0x29, 0x16, 0x75, 0x1B
         },
         {
            0xF1, 0xF7, 0xBF, 0x36, 0x7A, 0xC3, 0xA6, 0x7A, 0xE4, 0xEE, 0x86, 0x43, 0x9B, 0x1D, 0x32, 0xC0,
            0xF3, 0xF4, 0xD5, 0x8E, 0xD6, 0x5A, 0x9D, 0x29, 0x98, 0xB8, 0x70, 0x18, 0xFE, 0x87, 0x70, 0xAB
         }
      }
   };

#define NANO_TST_LST_SZ sizeof(SEED_TEST)/sizeof(struct seed_test_t)
   for (i=0;i<NANO_TST_LST_SZ;) {
      err=f_seed_to_nano_wallet(
         private_key_tmp,
         public_key_tmp,
         memcpy(seed_tmp, nano_seed.nano_seed_test, sizeof(nano_seed.nano_seed_test)),
         SEED_TEST[i].wallet_number
      );
      C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
         CTEST_SETTER(
            CTEST_INFO(
               "Checking if Nano ed25519 cryptographic key pair number %u are generated from SEED = \"%s\" successfully.",
               SEED_TEST[i].wallet_number, nano_seed.seed_name
            ),
            CTEST_ON_SUCCESS(
               "Wallet number: %u, private key \"%s\" and public key \"%s\"",
                SEED_TEST[i].wallet_number,
                fhex2strv2(msg1, private_key_tmp, 32, 0),
                fhex2strv2(msg2, public_key_tmp, 32, 0)
            )
         )
      )
      C_ASSERT_EQUAL_BYTE(SEED_TEST[i].private_key, private_key_tmp, 32,
         CTEST_SETTER(
            CTEST_INFO(
               "Checking generated private key at address %p is equal to expected private key at address %p",
               private_key_tmp, &SEED_TEST[i].private_key
            ),
            CTEST_ON_ERROR(
               "Was expected private key \"%s\" but found \"%s\"",
               fhex2strv2(msg1, SEED_TEST[i].private_key, 32, 0),
               fhex2strv2(msg2, private_key_tmp, 32, 0)
            )
         )
      )
      C_ASSERT_EQUAL_BYTE(SEED_TEST[i].public_key, public_key_tmp, 32,
         CTEST_SETTER(
            CTEST_INFO(
               "Checking generated public key at address %p is equal to expected public key at address %p",
               public_key_tmp, &SEED_TEST[i].public_key
            ),
            CTEST_ON_ERROR(
               "Was expected public key \"%s\" but found \"%s\"",
               fhex2strv2(msg1, SEED_TEST[i].public_key, 32, 0),
               fhex2strv2(msg2, public_key_tmp, 32, 0)
            )
         )
      )
      err=pk_to_wallet(msg1, SEED_TEST[i].nano_prefix, public_key_tmp);
      C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
         CTEST_SETTER(
            CTEST_INFO(
               "Checking if public key is converted to Nano address with prefix %s", SEED_TEST[i].nano_prefix
            ),
            CTEST_ON_SUCCESS(
               "Successfully generated wallet address \"%s\"", msg1
            ),
            CTEST_ON_ERROR(
               "Was expected ERROR_SUCCESS (%d) but found (%d)", ERROR_SUCCESS, err
            )
         )
      )
      C_ASSERT_EQUAL_STRING(SEED_TEST[i].address, msg1,
         CTEST_SETTER(
            CTEST_INFO(
               "Checking address (wallet number = %d) is correct with prefix %s",
               i, SEED_TEST[i].nano_prefix
            ),
            CTEST_ON_SUCCESS(
               "Wallet number %d wallet = %s SUCCESS !!!", i, SEED_TEST[i].address
            ),
            CTEST_ON_ERROR(
               "Was expected wallet = %s but found %s", SEED_TEST[i].address, msg1
            )
         )
      )
      C_ASSERT_TRUE(is_nano_prefix((const char *)msg1, (const char *)SEED_TEST[i].nano_prefix),
         CTEST_SETTER(
            CTEST_INFO("Checking if Nano prefix \"%s\" matches with \"%s\" ...", msg1, SEED_TEST[i].nano_prefix),
            CTEST_ON_ERROR(NANO_PREFIX_ERROR_MSG, C_TEST_TRUE, SEED_TEST[i].nano_prefix, msg1),
            CTEST_ON_SUCCESS(NANO_PREFIX_SUCCESS_MSG, C_TEST_TRUE, SEED_TEST[i].nano_prefix, msg1)
         )
      )
      i++;
   }
#undef NANO_TST_LST_SZ

#undef MSG_SZ

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
