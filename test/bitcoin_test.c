#include "common_test.h"

void bitcoin_address_test()
{
   int err;
   size_t sz;
   char *p;
   uint8_t *hash;

   memset(buf_msg, sizeof(buf_msg), 0);
   static uint8_t public_key[]={
      0x03,
      0x9c, 0x29, 0x35, 0xb8, 0xa7, 0x0f, 0x52, 0xe2, 0x97, 0x22, 0x51, 0x11, 0x87, 0xe5, 0x74, 0x6d,
      0x09, 0xdd, 0x6c, 0xe5, 0xdf, 0xc2, 0x6d, 0x22, 0xdb, 0x3b, 0x6d, 0xac, 0x3b, 0xb9, 0xba, 0x56
   };

   const char *address="15krkMzNo4e4TJbAZ9PSfxZCaZ7diP3iDY";

   p=&buf_msg[sizeof(buf_msg)>>1];

   err=f_public_key_to_address(buf_msg, sizeof(buf_msg), &sz, public_key, F_BITCOIN_P2PKH);

   C_ASSERT_EQUAL_INT(0, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_public_key_to_address\" to generate address from public key \"%s\" ...", fhex2strv2(p, public_key, sizeof(public_key), 1)),
         CTEST_ON_ERROR("f_public_key_to_address error  %d", err),
         CTEST_ON_SUCCESS("Success. \"f_public_key_to_address\" returned address \"%.*s\" with size %u", sz, buf_msg, sz)
      )
   );
   buf_msg[sz]=0;
   C_ASSERT_EQUAL_STRING(address, buf_msg,
      CTEST_SETTER(
         CTEST_INFO("Testing if generate address \"%.*s\" is matching ...", sz, buf_msg),
         CTEST_ON_ERROR("Wrong Bitcoin address string"),
         CTEST_ON_SUCCESS("Success. Bitcoin wallet \"%.*s\" matches with given public key \"%.*s\"", sz, buf_msg, sizeof(public_key)<<1, p)
      )
   );
}
