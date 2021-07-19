#include <common_test.h>

void bitcoin_address_test()
{
   int err;
   size_t sz;
   char *p;

   static uint8_t public_key[]={
      0x03,
      0x9c, 0x29, 0x35, 0xb8, 0xa7, 0x0f, 0x52, 0xe2, 0x97, 0x22, 0x51, 0x11, 0x87, 0xe5, 0x74, 0x6d,
      0x09, 0xdd, 0x6c, 0xe5, 0xdf, 0xc2, 0x6d, 0x22, 0xdb, 0x3b, 0x6d, 0xac, 0x3b, 0xb9, 0xba, 0x56
   };

   const char *address="15krkMzNo4e4TJbAZ9PSfxZCaZ7diP3iDY";

   p=msgbuf()+(BUF_MSG_SZ>>1);
   clear_msgbuf();

   err=f_check_if_invalid_btc_public_key(public_key);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_check_if_invalid_btc_public_key\" if public key \"%s\" is invalid ...", fhex2strv2(p, public_key, sizeof(public_key), 1)),
         CTEST_ON_ERROR("f_check_if_invalid_btc_public_key error  %d", err),
         CTEST_ON_SUCCESS("Success. \"f_check_if_invalid_btc_public_key\" returned success")
      )
   )

   err=f_public_key_to_address(msgbuf(), BUF_MSG_SZ>>1, &sz, public_key, F_BITCOIN_P2PKH);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_public_key_to_address\" to generate address from public key \"%s\" ...", p),
         CTEST_ON_ERROR("f_public_key_to_address error  %d", err),
         CTEST_ON_SUCCESS("Success. \"f_public_key_to_address\" returned address \"%.*s\" with size %u", sz, msgbuf(), sz)
      )
   )

   C_ASSERT_EQUAL_STRING(address, msgbuf(),
      CTEST_SETTER(
         CTEST_INFO("Testing if generate address \"%.*s\" is matching ...", sz, msgbuf()),
         CTEST_ON_ERROR("Wrong Bitcoin address string"),
         CTEST_ON_SUCCESS("Success. Bitcoin wallet \"%.*s\" matches with given public key \"%.*s\"", sz, msgbuf(), sizeof(public_key)<<1, p)
      )
   )
}

void xpriv_xpub_test()
{
// Based on test https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
   int err;
   const char *entropy_128="000102030405060708090a0b0c0d0e0f";
   uint8_t *buffer_test=(uint8_t *)msgbuf();
   char *key, *p;
   BITCOIN_SERIALIZE *btc_ser=(BITCOIN_SERIALIZE *)(msgbuf()+(BUF_MSG_SZ>>1));

   clear_msgbuf();

   err=f_str_to_hex(buffer_test, (char *)entropy_128);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Parsing \"%s\" to binary hex", entropy_128)
      )
   )

   err=f_load_from_master_key_from_entropy_bits(
      btc_ser,
      MAINNET_PRIVATE,
      (const uint8_t *)buffer_test,
      MK_128
   );

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO(
            "Load from master key \"%s\" ...",
            entropy_128
         ),
         CTEST_ON_SUCCESS(
            "BITCOIN_SERIALIZE at %p size = %u success", 
            btc_ser,
            sizeof(BITCOIN_SERIALIZE)
         ),
         CTEST_ON_ERROR(
            "Was expected ERROR_SUCCESS(%d) but found %d",
            ERROR_SUCCESS,
            err
         )
      )
   )

   err=f_derive_xkey_dynamic((void **)&key, btc_ser, "m/0", DERIVE_XPRIV_XPUB_DYN_OUT_BASE58|DERIVE_XPRIV_XPUB_DYN_OUT_XPRIV);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO(
            "Deriving key for \"btc_ser\" at %p",
            btc_ser
         ),
         CTEST_ON_SUCCESS(
            "\"key\" at %p successful \"%s\"",
            key,
            OR_ELSE_NULL_STR(key)
         ),
         CTEST_ON_ERROR(
            "Was expected ERROR_SUCCESS(%d) but found %d for \"f_derive_xkey_dynamic\"",
            ERROR_SUCCESS,
            err
         )
      )
   )
// TODO IMPLEMENT THIS
   free(key);

}
