//fri apr 23 21:34:27 -03 2021 sex abr 23 21:34:29 -03 2021 
#include "common_test.h"
#include "bitcoin_test.h"
#include "uncompress_ecc_test.h"

//gcc -o test main.c ../src/ctest/asserts.c -I../include -I../include/sodium -I../include/ctest -L../lib -lnanocrypto1 -lsodium -fsanitize=leak,address
//gcc -o test main.c ../src/ctest/asserts.c bitcoin_test.c common_test.c uncompress_ecc_test.c -I../include -I../include/sodium -I../include/ctest -lsodium -lnanocrypto1 -Wall -L../lib

int main (int argc, char **argv)
{
   int err;
   char buf[512];
   const char *password="This is a strong word for PASSWORD";
   const char *name="Nikola Tesla", *name_invalid="nikola tesla";
   F_TOKEN token;

   err=f_generate_token(token, (void *)name, sizeof(name)-1, password);

   C_ASSERT_EQUAL_INT(3858, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_generate_token\" a non deterministic token generator when misconfigured random number generator ..."),
         CTEST_WARN("This function should always return error 3858 when there is no random number generator configured by user"),
         CTEST_ON_ERROR("It should return error 3858 when no random number generator is configured"),
         CTEST_ON_SUCCESS("Success. \"f_generate_token\" returned no random number generator misconfiguration error")
      )
   );

   f_random_attach(gen_rand_no_entropy);
   err=f_generate_token(token, (void *)name, sizeof(name)-1, password);
   C_ASSERT_EQUAL_INT(0, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_generate_token\" when success ..."),
         CTEST_ON_ERROR("It should return error 0 (SUCCESS) when random number generator is configured"),
         CTEST_ON_SUCCESS("Success. \"f_generate_token\" returned generated non deterministic token \"%s\"", fhex2strv2(buf, token, sizeof(token), 0))
      )
   );
   f_random_detach();

   err=f_verify_token(token, (void *)name, sizeof(name)-1, password);
   C_ASSERT_EQUAL_INT(1, err,
      CTEST_SETTER(
         CTEST_INFO("Testing generated token \"%s\" is valid with \"f_verify_token\" ...", buf),
         CTEST_ON_ERROR("It should return TRUE (1) with token \"%s\"", buf),
         CTEST_ON_SUCCESS("Success. \"f_verify_token\" returned valid token \"%s\"", buf)
      )
   );

   err=f_verify_token(token, (void *)name_invalid, sizeof(name_invalid)-1, password);
   C_ASSERT_EQUAL_INT(0, err,
      CTEST_SETTER(
         CTEST_INFO("Testing generated token \"%s\" is valid with \"f_verify_token\" and invalid name ...", buf),
         CTEST_WARN("This should return 0 (FALSE) for invalid string name"),
         CTEST_ON_ERROR("It should return FALSE (0) with token \"%s\"", buf),
         CTEST_ON_SUCCESS("Success. \"f_verify_token\" returned invalid token check for invalid name \"%s\"", buf)
      )
   );

   printf("\nTesting uncompress elliptic curve for Bitcoin ...\n");
   uncompress_eliptic_curve_test();

   printf("\nInitiating Bitcoin test ...\n");

   bitcoin_address_test();

   end_tests();

   return 0;
}

