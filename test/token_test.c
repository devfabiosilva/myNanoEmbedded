#include <common_test.h>

void token_test()
{
   int err;
   char buf[512];
   const char password[]="This is a strong word for PASSWORD";
   const char name[]="Nikola Tesla", name_invalid[]="nikola tesla";
   F_TOKEN token;

   C_ASSERT_EQUAL_INT(
      ERROR_GEN_TOKEN_NO_RAND_NUM_GEN,
      f_generate_token(token, (void *)name, sizeof(name)-1, password),
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_generate_token\" a non deterministic token generator when misconfigured random number generator ..."),
         CTEST_WARN(
            "This function should always return error \"ERROR_GEN_TOKEN_NO_RAND_NUM_GEN\" (%d) when there is no random number generator configured by user",
            ERROR_GEN_TOKEN_NO_RAND_NUM_GEN
         ),
         CTEST_ON_ERROR(
            "It should return error \"ERROR_GEN_TOKEN_NO_RAND_NUM_GEN\" (%d) when no random number generator is configured", 
             ERROR_GEN_TOKEN_NO_RAND_NUM_GEN
         ),
         CTEST_ON_SUCCESS("Success. \"f_generate_token\" returned no random number generator misconfiguration error")
      )
   );

   f_random_attach(gen_rand_no_entropy);
   err=f_generate_token(token, (void *)name, sizeof(name)-1, password);
   C_ASSERT_EQUAL_INT(
      ERROR_SUCCESS,
      err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_generate_token\" when success ..."),
         CTEST_ON_ERROR("It should return error %d (ERROR_SUCCESS) when random number generator is configured", ERROR_SUCCESS),
         CTEST_ON_SUCCESS("Success. \"f_generate_token\" returned generated non deterministic token \"%s\"", fhex2strv2(buf, token, sizeof(token), 0))
      )
   )
   f_random_detach();

   C_ASSERT_TRUE(
      f_verify_token(token, (void *)name, sizeof(name)-1, password),
      CTEST_SETTER(
         CTEST_INFO("Testing generated token \"%s\" is valid with \"f_verify_token\" ...", buf),
         CTEST_ON_ERROR("It should return TRUE (%d) with token \"%s\"", C_TEST_TRUE, buf),
         CTEST_ON_SUCCESS("Success. \"f_verify_token\" returned valid token \"%s\"", buf)
      )
   )

   C_ASSERT_FALSE(
      f_verify_token(token, (void *)name_invalid, sizeof(name_invalid)-1, password),
      CTEST_SETTER(
         CTEST_INFO("Testing generated token \"%s\" is valid with \"f_verify_token\" and invalid name ...", buf),
         CTEST_WARN("This should return %d (FALSE) for invalid string name", C_TEST_FALSE),
         CTEST_ON_ERROR("It should return FALSE (%d) with token \"%s\"", C_TEST_FALSE, buf),
         CTEST_ON_SUCCESS("Success. \"f_verify_token\" returned invalid token check for invalid name \"%s\"", buf)
      )
   )
}
