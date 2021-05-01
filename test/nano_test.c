#include <common_test.h>

#define NANO_PREFIX_ERROR_MSG "\"is_nano_prefix\" should return TRUE (%d) for prefix \"%s\" for this wallet: \"%s\""
#define NANO_PREFIX_SUCCESS_MSG "\"is_nano_prefix\" returned TRUE (%d) for prefix \"%s\" for this wallet: \"%s\""
#define GENESIS_PREVIOUS (uint8_t [])\
                         {\
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00\
                         }

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
      {
         0xC7, 0xE0, 0x71, 0x95, 0xBF, 0xAA, 0x93, 0xA0, 0xF7, 0xB8, 0xA1, 0x06, 0x95, 0x7C, 0x64, 0xD4,
         0x62, 0x6B, 0x10, 0xA2, 0x0B, 0x01, 0x0C, 0x5D, 0xEA, 0x0F, 0x68, 0xCD, 0x98, 0x44, 0xD0, 0x34
      }
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
      },
      {
         "nano_1uj9f5hazjrzrgbp46ainirjmmhsuqn3ohsz63uusem18runsqzrdj6yydxh",
         NANO_PREFIX,
         5,
         {
            0xD7, 0x19, 0xA8, 0x7F, 0x22, 0x81, 0x50, 0xBB, 0x4B, 0x30, 0x95, 0x7E, 0x17, 0x8A, 0xA9, 0x53,
            0x39, 0x8B, 0xE4, 0x3D, 0x88, 0xB0, 0x16, 0x29, 0xC9, 0x82, 0x5D, 0xCA, 0x50, 0x8C, 0x48, 0xF0
         },
         {
            0x6E, 0x27, 0x68, 0xDE, 0x8F, 0xC7, 0x1F, 0xC3, 0x93, 0x61, 0x11, 0x10, 0xA4, 0x31, 0x19, 0xCD,
            0xF9, 0xDD, 0xE8, 0x1A, 0xBF, 0x3F, 0x20, 0x77, 0xBC, 0xB2, 0x60, 0x36, 0x37, 0x4C, 0xDF, 0xF8
         }
      },
      {
         "xrb_3jx159p55nwebxyew4988akaps7iqpa51z77xa5zyfo5cnhi5hj49qkimjt6",
         XRB_PREFIX,
         1981,
         {
            0xCF, 0xF3, 0x15, 0xE5, 0xF1, 0x33, 0xF3, 0x08, 0xCC, 0xD0, 0x4A, 0xB4, 0x05, 0x57, 0x92, 0xEE,
            0xC2, 0x5A, 0x35, 0xDE, 0x08, 0x14, 0xAD, 0xC4, 0x24, 0xB9, 0x1B, 0xEA, 0x8E, 0xB6, 0xCA, 0x18
         },
         {
            0xC7, 0xA0, 0x19, 0xEC, 0x31, 0xD3, 0x8C, 0x4F, 0x7C, 0xCE, 0x08, 0xE6, 0x32, 0x24, 0x8B, 0x64,
            0xB0, 0xBD, 0x90, 0x30, 0x7C, 0xA5, 0xEA, 0x07, 0xFF, 0x36, 0xA3, 0x55, 0x1F, 0x01, 0xBE, 0x22
         }
      },
      {
         "nano_3ectzfayryse3gjtn8b9bn3jm41jchwy5xce4usoq1garmbbp5a314y674zz",
         NANO_PREFIX,
         10000,
         {
            0xE4, 0x3B, 0xE6, 0x7F, 0x55, 0xBF, 0x53, 0x73, 0xAA, 0x72, 0x44, 0x53, 0xE7, 0x68, 0x92, 0x73,
            0x18, 0xFE, 0xA5, 0xDA, 0x66, 0x64, 0x30, 0x01, 0x95, 0xD3, 0x21, 0x4D, 0xBC, 0xED, 0x31, 0xE7
         },
         {
            0xB1, 0x5A, 0xFB, 0x51, 0xEC, 0x7B, 0x2C, 0x0B, 0xA3, 0xAA, 0x19, 0x27, 0x4D, 0x03, 0x19, 0x88,
            0x11, 0x53, 0xF9, 0xE1, 0xF5, 0x4C, 0x16, 0xF3, 0x5B, 0x81, 0xC8, 0xC4, 0xD2, 0x9B, 0x0D, 0x01
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
               "Checking address (wallet number = %u) is correct with prefix %s",
               SEED_TEST[i].wallet_number, SEED_TEST[i].nano_prefix
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

static void close_block(void *ctx)
{
   printf("\nError occurs\n");
   if (ctx) {
      printf("\nFreeing Nano block at address (%p)...\n", ctx);
      free(ctx);
   }
}

void nano_block_test()
{
   int err, i;
   F_BLOCK_TRANSFER *block;
   static const char
      *account="nano_1uj9f5hazjrzrgbp46ainirjmmhsuqn3ohsz63uusem18runsqzrdj6yydxh",
      *previous="46ca895be3a18fb50c1c6b5a3bd2e97fb637b35a22924c2f3dea3cf09e9e2e74",
      *representative="xrb_3jx159p55nwebxyew4988akaps7iqpa51z77xa5zyfo5cnhi5hj49qkimjt6",
      *balance="273.1000120000283700018",
      *value_to_send="177.17",
      *value_to_receive="17388.18266381",
      *address_to_send="xrb_16hsbha1tixrxyjrrf618qjr31cpwbisa8s4boj9916uj5e6to7oxkizghgc",
      *link="cad2eabfd8aea39e7c9ec2f041d502150ccbe7202673c3fb1fe60ec029d323ce";

   struct block_info_t {
      int expected_error;
      const char
         *message_warning,
         *message_on_success,
         *message_on_error;
      const void
         *account;
      size_t
         account_len;
      const void
         *previous;
      size_t
         previous_len;
      const void
         *representative;
      size_t
         representative_len;
      void
         *balance,
         *value_to_send_or_receive;
      uint32_t
         values_type;
      void
         *link;
      size_t
         link_len;
      int direction;
   } BLOCK_INFO[] = {
      {
         NANO_CREATE_BLK_DYN_GENESIS_WITH_NON_EMPTY_BALANCE,
         "This would expect an error. Because it does not make sense create a genesis block to send Nano with balance. Trying with NULL",
         "Error success, expected error NANO_CREATE_BLK_DYN_GENESIS_WITH_NON_EMPTY_BALANCE (%d)",
         "Error fail. Was expected NANO_CREATE_BLK_DYN_GENESIS_WITH_NON_EMPTY_BALANCE (%d), but found (%d)",
         (void *)account, 0, 
         (void *)NULL, 0,
         (void *)representative, 0,
         (void *)balance,
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_RECEIVE
      },
      {
         NANO_ERR_INSUFICIENT_FUNDS,
         "This would expect an error. Because this account does not have suficient funds to send",
         "Error success, expected error NANO_ERR_INSUFICIENT_FUNDS (%d)",
         "Error fail. Was expected NANO_ERR_INSUFICIENT_FUNDS (%d), but found (%d)",
         (void *)account, 0, 
         (void *)previous, 0,
         (void *)representative, 0,
         (void *)"100",
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_SEND
      },
      {
         NANO_ACCOUNT_BASE32_CONVERT_ERROR,
         "This would expect an error. Because this account is an invalid address",
         "Error success, expected error NANO_ACCOUNT_BASE32_CONVERT_ERROR (%d)",
         "Error fail. Was expected NANO_ACCOUNT_BASE32_CONVERT_ERROR (%d), but found (%d)",
         (void *)"nano_15hsbha1tixrxyjrrf618qjr31cpwbisa8s4boj9916uj5e6to7oxkizghgc", 0, 
         (void *)previous, 0,
         (void *)representative, 0,
         (void *)"1526.187366",
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_SEND
      },
      {
         ERROR_SUCCESS,
         "This would expect a success. Parsing address with 32 bytes (raw data)",
         "Error success, expected error ERROR_SUCCESS (%d)",
         "Error fail. Was expected ERROR_SUCCESS (%d), but found (%d)",
         (void *)(uint8_t [])
                  {
                     0xF1, 0xF7, 0xBF, 0x36, 0x7A, 0xC3, 0xA6, 0x7A, 0xE4, 0xEE, 0x86, 0x43, 0x9B, 0x1D, 0x32, 0xC0,
                     0xF3, 0xF4, 0xD5, 0x8E, 0xD6, 0x5A, 0x9D, 0x29, 0x98, 0xB8, 0x70, 0x18, 0xFE, 0x87, 0x70, 0xAB
                  }, 32, 
         (void *)previous, 0,
         (void *)representative, 0,
         (void *)"1526.187366",
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_SEND
      },
      {
         ERROR_SUCCESS,
         "This would expect a success. Parsing hex string account",
         "Error success, expected error ERROR_SUCCESS (%d) for hex string account",
         "Error fail. Was expected ERROR_SUCCESS (%d) for hex string account, but found (%d)",
         (void *) "F1F7BF367AC3A67AE4EE86439B1D32C0F3F4D58ED65A9D2998B87018FE8770AB", 0,
         (void *)previous, 0,
         (void *)representative, 0,
         (void *)"1526.187366",
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_SEND
      },
      {
         NANO_ACCOUNT_WRONG_HEX_STRING,
         "This would expect an error. Invalid HEX string account",
         "Error success, expected error NANO_ACCOUNT_WRONG_HEX_STRING (%d) for invalid hex string account",
         "Error fail. Was expected NANO_ACCOUNT_WRONG_HEX_STRING (%d) for invalid hex string account, but found (%d)",
         (void *) "K1F7BF367AC3A67AE4EE86439B1D32C0F3F4D58ED65A9D2998B87018FE8770AB", 0,
         (void *)previous, 0,
         (void *)representative, 0,
         (void *)"1526.187366",
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_SEND
      },
      {
         NANO_CREATE_BLK_DYN_COMPARE,
         "This would expect an error. Because this account has negative value to send",
         "Error success, expected error NANO_CREATE_BLK_DYN_COMPARE (%d)",
         "Error fail. Was expected NANO_CREATE_BLK_DYN_COMPARE (%d), but found (%d)",
         (void *)account, 0, 
         (void *)previous, 0,
         (void *)representative, 0,
         (void *)"60000.012",
         (void *)"-10.18", F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_RECEIVE
      },
      {
         NANO_CREATE_BLK_DYN_COMPARE,
         "This would expect an error. Because this account has invalid big number format",
         "Error success, expected error NANO_CREATE_BLK_DYN_COMPARE (%d) invalid -> ok",
         "Error fail. Was expected NANO_CREATE_BLK_DYN_COMPARE (%d), but found (%d) -> fail",
         (void *)account, 0,
         (void *)previous, 0,
         (void *)representative, 0,
         (void *)"60200.012",
         (void *)"-10acsa18", F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_RECEIVE
      },
      {
         ERROR_SUCCESS,
         "This would expect a success. Parsing a valid raw string balance",
         "Error success, expected error ERROR_SUCCESS (%d) for valid raw string balance",
         "Error fail. Was expected ERROR_SUCCESS (%d), but found (%d) for valid raw string balance -> fail",
         (void *)account, 0,
         (void *)previous, 0,
         (void *)representative, 0,
         (void *)"1234560000000000000000000000001",
         (void *)"1929.28710017", F_BALANCE_RAW_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_RECEIVE
      },
#define GENESIS_BLOCK_SUCCESS_MSG "Error success, expected error NANO_CREATE_BLK_DYN_CANT_SEND_IN_GENESIS_BLOCK (%d)"
#define GENESIS_BLOCK_ERROR_MSG "Error fail. Was expected NANO_CREATE_BLK_DYN_CANT_SEND_IN_GENESIS_BLOCK (%d), but found (%d)"
      {
         NANO_CREATE_BLK_DYN_CANT_SEND_IN_GENESIS_BLOCK,
         "This would expect an error. Because it does not make sense create a genesis block to send Nano with 0.0 balance. Trying strings with 0's",
         GENESIS_BLOCK_SUCCESS_MSG,
         GENESIS_BLOCK_ERROR_MSG,
         (void *)account, 0, 
         (void *)"0000000000000000000000000000000000000000000000000000000000000000", 0,
         (void *)representative, 0,
         (void *)balance,
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_SEND
      },
      {
         NANO_CREATE_BLK_DYN_CANT_SEND_IN_GENESIS_BLOCK,
         "This would expect an error. Because it does not make sense create a genesis block to send Nano with 0.0 balance. Trying raw with 0's",
         GENESIS_BLOCK_SUCCESS_MSG,
         GENESIS_BLOCK_ERROR_MSG,
         (void *)account, 0, 
         (void *)GENESIS_PREVIOUS, sizeof(GENESIS_PREVIOUS),
         (void *)representative, 0,
         (void *)balance,
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_SEND
      },
      {
         NANO_CREATE_BLK_DYN_CANT_SEND_IN_GENESIS_BLOCK,
         "This would expect an error. Because it does not make sense create a genesis block to send Nano with 0.0 balance. Trying with NULL",
         GENESIS_BLOCK_SUCCESS_MSG,
         GENESIS_BLOCK_ERROR_MSG,
         (void *)account, 0, 
         (void *)NULL, 0,
         (void *)representative, 0,
         (void *)balance,
         (void *)value_to_send, F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
         (void *)link, 0,
         F_VALUE_TO_SEND
      }
#undef GENESIS_BLOCK_ERROR_MSG
#undef GENESIS_BLOCK_SUCCESS_MSG
   };

#define BLOCK_INFO_SZ sizeof(BLOCK_INFO)/sizeof(BLOCK_INFO[0])

   err=nano_create_block_dynamic(
      NULL,
      account,
      0,
      previous,
      0,
      representative,
      0,
      balance,
      value_to_receive,
      F_BALANCE_REAL_STRING|F_VALUE_SEND_RECEIVE_REAL_STRING,
      link,
      0,
      F_VALUE_TO_RECEIVE
   );

   C_ASSERT_EQUAL_INT(NANO_CREATE_BLK_DYN_BLOCK_NULL, err,
      CTEST_SETTER(
         CTEST_WARN(
            "Expecting error NANO_CREATE_BLK_DYN_BLOCK_NULL (%d) from \"nano_create_block_dynamic\" due to invalid NULL block",
            NANO_CREATE_BLK_DYN_BLOCK_NULL
         ),
         CTEST_ON_ERROR("Was expected NANO_CREATE_BLK_DYN_BLOCK_NULL (%d) but found (%d)", NANO_CREATE_BLK_DYN_BLOCK_NULL, err),
         CTEST_ON_SUCCESS("NANO_CREATE_BLK_DYN_BLOCK_NULL (%d) expected success", NANO_CREATE_BLK_DYN_BLOCK_NULL)
      )
   )

   for (i=0;i<BLOCK_INFO_SZ;) {
      INFO_MSG_FMT("---- Entering block index %d of %d ----", i, BLOCK_INFO_SZ-1)
      err=nano_create_block_dynamic(
         &block,
         BLOCK_INFO[i].account,
         BLOCK_INFO[i].account_len,
         BLOCK_INFO[i].previous,
         BLOCK_INFO[i].previous_len,
         BLOCK_INFO[i].representative,
         BLOCK_INFO[i].representative_len,
         BLOCK_INFO[i].balance,
         BLOCK_INFO[i].value_to_send_or_receive,
         BLOCK_INFO[i].values_type,
         BLOCK_INFO[i].link,
         BLOCK_INFO[i].link_len,
         BLOCK_INFO[i].direction
      );

      C_ASSERT_EQUAL_INT(BLOCK_INFO[i].expected_error, err,
         CTEST_SETTER(
            CTEST_WARN(BLOCK_INFO[i].message_warning),
            CTEST_ON_SUCCESS(BLOCK_INFO[i].message_on_success, BLOCK_INFO[i].expected_error),
            CTEST_ON_ERROR(BLOCK_INFO[i].message_on_error, BLOCK_INFO[i].expected_error, err),
            CTEST_ON_ERROR_CB(close_block, block)
         )
      )

      if (err!=ERROR_SUCCESS)
         C_ASSERT_NULL(block,
            CTEST_SETTER(
               CTEST_INFO("Checking if block==NULL if err(%d)!=ERROR_SUCCESS(%d)", err, ERROR_SUCCESS),
               CTEST_ON_ERROR("Block should be NULL if err!=ERROR_SUCCESS"),
               CTEST_ON_SUCCESS("Success. block==NULL"),
               CTEST_ON_ERROR_CB(close_block, block)
            )
         )
      else
         C_ASSERT_NOT_NULL(block,
            CTEST_SETTER(
               CTEST_INFO("Checking if block!=NULL if err(%d)==ERROR_SUCCESS(%d)", err, ERROR_SUCCESS),
               CTEST_ON_ERROR("Block should NOT be NULL if err==ERROR_SUCCESS"),
               CTEST_ON_SUCCESS("Success. block(%p)!=NULL", block)
            )
         )

      if (block) {
         printf("\nClosing block of index %d (%p)...\n", i, block);
         free(block);
      }

      i++;
   }

#undef BLOCK_INFO_SZ

}
