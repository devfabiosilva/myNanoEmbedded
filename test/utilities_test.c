#include <common_test.h>

void url_decode_test()
{
   int err;
   size_t dest_sz;

   clear_msgbuf();

   err=f_url_decode(msgbuf(), BUF_MSG_SZ, &dest_sz, "%", 0);

   C_ASSERT_EQUAL_INT(F_URL_ENCODE_WAITING_NEXT_NIBBLE, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_url_decode\". Is expected F_URL_ENCODE_WAITING_NEXT_NIBBLE (%d) error", F_URL_ENCODE_WAITING_NEXT_NIBBLE),
         CTEST_ON_ERROR("Was expected error in \"f_url_decode\" F_URL_ENCODE_WAITING_NEXT_NIBBLE (%d), but found (%d)", F_URL_ENCODE_WAITING_NEXT_NIBBLE, err),
         CTEST_ON_SUCCESS("Success. \"f_url_decode\" returned success")
      )
   )

   err=f_url_decode(msgbuf(), BUF_MSG_SZ, &dest_sz, "", 0);

   C_ASSERT_EQUAL_INT(F_URL_ENCODE_EMPTY_STRING, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_url_decode\". Is expected F_URL_ENCODE_EMPTY_STRING (%d) error", F_URL_ENCODE_EMPTY_STRING),
         CTEST_ON_ERROR("Was expected error in \"f_url_decode\" F_URL_ENCODE_WAITING_NEXT_NIBBLE (%d), but found (%d)", F_URL_ENCODE_EMPTY_STRING, err),
         CTEST_ON_SUCCESS("Success. \"f_url_decode\" returned success for null string")
      )
   )

   err=f_url_decode(msgbuf(), BUF_MSG_SZ, &dest_sz, "Bitcoin", 0);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_url_decode\". Is expected ERROR_SUCCESS (%d)", ERROR_SUCCESS),
         CTEST_ON_ERROR("Was expected \"f_url_decode\" ERROR_SUCCESS (%d), but found (%d)", ERROR_SUCCESS, err),
         CTEST_ON_SUCCESS("Success. \"f_url_decode\" for a simple word")
      )
   )
#define BITCOIN "Bitcoin"
   C_ASSERT_EQUAL_STRING(BITCOIN, msgbuf(),
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_url_decode\". Is expected \"Bitcoin\""),
         CTEST_ON_ERROR("Was expected \"Bitcoin\", but found \"%s\"", msgbuf()),
         CTEST_ON_SUCCESS("Success. \"f_url_decode\"")
      )
   )

   C_ASSERT_EQUAL_INT((int)(sizeof(BITCOIN)-1), (int)dest_sz,
      CTEST_SETTER(
         CTEST_INFO("Testing \"dest_sz\" is size %d", (int)(sizeof(BITCOIN)-1)),
         CTEST_ON_ERROR("Was expected dest_sz = %d, but dest_sz = %d", (int)(sizeof(BITCOIN)-1), (int)dest_sz),
         CTEST_ON_SUCCESS("Success. \"dest_sz\" for \""BITCOIN"\" string size")
      )
   )

#define BITCOIN_IS_COOL "Bitcoin is cool"
   err=f_url_decode(msgbuf(), BUF_MSG_SZ, &dest_sz, BITCOIN_IS_COOL, 0);

   C_ASSERT_EQUAL_INT(F_URL_ENCODE_INVALID_STRING, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_url_decode\". Is expected F_URL_ENCODE_INVALID_STRING (%d)", F_URL_ENCODE_INVALID_STRING),
         CTEST_ON_ERROR("Was expected \"f_url_decode\" F_URL_ENCODE_INVALID_STRING (%d), but found (%d)", F_URL_ENCODE_INVALID_STRING, err),
         CTEST_ON_SUCCESS("Success. \"f_url_decode\" for invalid URL decode")
      )
   )

#define BITCOIN_IS_COOL_URL_ENCODED "Bitcoin%20is%20cool"
   err=f_url_decode(msgbuf(), BUF_MSG_SZ, &dest_sz, BITCOIN_IS_COOL_URL_ENCODED, 0);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_url_decode\". Is expected ERROR_SUCCESS (%d)", ERROR_SUCCESS),
         CTEST_ON_ERROR("Was expected \"f_url_decode\" ERROR_SUCCESS (%d), but found (%d)", ERROR_SUCCESS, err),
         CTEST_ON_SUCCESS("Success. \"f_url_decode\" for valid URL decode")
      )
   )

   C_ASSERT_EQUAL_INT((int)(sizeof(BITCOIN_IS_COOL)-1), (int)dest_sz,
      CTEST_SETTER(
         CTEST_INFO("Testing \"dest_sz\" is size %d", (int)(sizeof(BITCOIN_IS_COOL)-1)),
         CTEST_ON_ERROR("Was expected dest_sz = %d, but dest_sz = %d", (int)(sizeof(BITCOIN_IS_COOL)-1), (int)dest_sz),
         CTEST_ON_SUCCESS("Success. \"dest_sz\" for \""BITCOIN_IS_COOL"\" string size")
      )
   )

   C_ASSERT_EQUAL_STRING(BITCOIN_IS_COOL, msgbuf(),
      CTEST_SETTER(
         CTEST_INFO("Testing \"f_url_decode\". Is expected \""BITCOIN_IS_COOL"\""),
         CTEST_ON_ERROR("Was expected \""BITCOIN_IS_COOL"\", but found \"%s\"", msgbuf()),
         CTEST_ON_SUCCESS("Success. \"f_url_decode\"")
      )
   )
#undef BITCOIN_IS_COOL_URL_ENCODED
#undef BITCOIN_IS_COOL
#undef BITCOIN
}

void password_strength_test()
{
   int err;
   char *password;
   size_t n, min, max;

   clear_msgbuf();

   TITLE_MSG("Entering password tests ...")
#define PASSWORD_MSG "Testing PASSWORD = \"%s\" with n = %u, min = %u and max = %u. %s"
#define PASSWORD_SUCCESS "Password success"
   err=f_pass_must_have_at_least(password="password", n=8, min=3, max=7, F_PASS_MUST_HAVE_AT_LEAST_NONE);
   C_ASSERT_EQUAL_INT(F_PASS_IS_OUT_OVF, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "Password overflow should be expected"),
         CTEST_ON_ERROR("Was expected error F_PASS_IS_OUT_OVF (%d). But found %d", F_PASS_IS_OUT_OVF, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password, n=9, min, max, F_PASS_MUST_HAVE_AT_LEAST_NONE);
   C_ASSERT_EQUAL_INT(F_PASS_IS_TOO_LONG, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "Password is too long"),
         CTEST_ON_ERROR("Was expected error F_PASS_IS_TOO_LONG (%d). But found %d", F_PASS_IS_TOO_LONG, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password, n=15, min=9, max=10, F_PASS_MUST_HAVE_AT_LEAST_NONE);
   C_ASSERT_EQUAL_INT(F_PASS_IS_TOO_SHORT, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "Password is too short"),
         CTEST_ON_ERROR("Was expected error F_PASS_IS_TOO_SHORT (%d). But found %d", F_PASS_IS_TOO_SHORT, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password, n, min=8, max, F_PASS_MUST_HAVE_AT_LEAST_NONE);
   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "Password with no criteria"),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d", ERROR_SUCCESS, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password, n, min, max, F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE);
   C_ASSERT_EQUAL_INT(F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE"),
         CTEST_ON_ERROR("Was expected error F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE (%d). But found %d", F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password="PASSWORD", n, min, max, F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE);
   C_ASSERT_EQUAL_INT(F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE"),
         CTEST_ON_ERROR("Was expected error F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE (%d). But found %d", F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password="PASSWORD-abc", n, min, max=14, F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE);
   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "ERROR_SUCCESS"),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d", ERROR_SUCCESS, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password, n, min, max, F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER);
   C_ASSERT_EQUAL_INT(F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER"),
         CTEST_ON_ERROR("Was expected error F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER (%d). But found %d", F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password="password1", n, min, max, F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER);
   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "ERROR_SUCCESS"),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d", ERROR_SUCCESS, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password, n, min, max, F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL);
   C_ASSERT_EQUAL_INT(F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL"),
         CTEST_ON_ERROR("Was expected error F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL (%d). But found %d", F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password="test@abc", n, min, max, F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL);
   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "ERROR_SUCCESS"),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d", ERROR_SUCCESS, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

#define PARANOIC \
   (F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL|F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER|F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE)
#define PARANOIC_STR \
   "F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL, F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER, F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE"

   err=f_pass_must_have_at_least(password="test", n, min=4, max, PARANOIC);
   C_ASSERT_EQUAL_INT(PARANOIC, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, PARANOIC_STR),
         CTEST_ON_ERROR("Was expected error (%d). But found %d", PARANOIC, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )

   err=f_pass_must_have_at_least(password="Test@1", n, min, max, PARANOIC);
   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_WARN(PASSWORD_MSG, password, n, min, max, "ERROR_SUCCESS"),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d", ERROR_SUCCESS, err),
         CTEST_ON_SUCCESS(PASSWORD_SUCCESS)
      )
   )
#undef PARANOIC_STR
#undef PARANOIC
#undef PASSWORD_SUCCESS
#undef PASSWORD_MSG
}

#define ARRAY_SIZE (size_t)32
struct mbedtls_test_t {
   mbedtls_mpi 
      X,
      A,
      B;
   uint8_t
      xArray[ARRAY_SIZE],
      aArray[ARRAY_SIZE],
      bArray[ARRAY_SIZE];
} *mbedtls_test;

static void nano_embedded_mbedtls_free_test(void *ctx)
{
   struct mbedtls_test_t *v=(struct mbedtls_test_t *)ctx;
   
   printf("\nError occurred in mbedTLS big number. Freeing vector (%p)\n\n", v);
   mbedtls_mpi_free(&v->B);
   mbedtls_mpi_free(&v->A);
   mbedtls_mpi_free(&v->X);

   free(v);

}

void nano_embedded_mbedtls_bn_test()
{
   int err;
   mbedtls_mpi_sint tmp;
   #define MBEDTLS_TEST_SIZE sizeof(struct mbedtls_test_t)

   mbedtls_test=malloc(MBEDTLS_TEST_SIZE);

   C_ASSERT_NOT_NULL(mbedtls_test,
      CTEST_SETTER(
         CTEST_INFO("Testing pointer for test \"mbedtls_test\"(%p) of size = %lu", mbedtls_test, MBEDTLS_TEST_SIZE)
      )
   )

   #define INITIAL_BYTE (uint8_t)0xAB

   memset(mbedtls_test, INITIAL_BYTE, MBEDTLS_TEST_SIZE);

   mbedtls_mpi_init(&mbedtls_test->X);
   mbedtls_mpi_init(&mbedtls_test->A);
   mbedtls_mpi_init(&mbedtls_test->B);

   #define A_VALUE (mbedtls_mpi_sint)0xFF
   #define B_VALUE (mbedtls_mpi_sint)0xEF

   err=mbedtls_mpi_lset(&mbedtls_test->A, A_VALUE);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Loading big number value \"A_VALUE\" =  %d", A_VALUE),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d for mbedtls_mpi_lset loading A value", ERROR_SUCCESS, err),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   err=mbedtls_mpi_lset(&mbedtls_test->B, B_VALUE);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Loading big number value \"B_VALUE\" =  %d", B_VALUE),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d for mbedtls_mpi_lset loading B value", ERROR_SUCCESS, err),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   err=mbedtls_mpi_add_mpi(&mbedtls_test->X, &mbedtls_test->A, &mbedtls_test->B);

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Adding X(%d) = A(%d) + B(%d)", A_VALUE+B_VALUE, A_VALUE, B_VALUE),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d for mbedtls_mpi_add_mpi", ERROR_SUCCESS, err),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   err=mbedtls_mpi_write_binary(&mbedtls_test->A, (unsigned char *)mbedtls_test->aArray, sizeof(mbedtls_test->aArray));

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Wrinting A value to array A at pointer (%p) of size %lu", mbedtls_test->aArray, sizeof(mbedtls_test->aArray)),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d for mbedtls_mpi_write_binary when write A value", ERROR_SUCCESS, err),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   tmp=(mbedtls_mpi_sint)mbedtls_test->aArray[ARRAY_SIZE-1];

   C_ASSERT_TRUE(tmp==A_VALUE,
      CTEST_SETTER(
         CTEST_INFO(
            "Checking if \"mbedtls_test->aArray[ARRAY_SIZE-1]\" = %d is equal to A_VALUE = %d",
            tmp, A_VALUE
         ),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   C_ASSERT_TRUE(is_filled_with_value(mbedtls_test->aArray, ARRAY_SIZE-1, 0),
      CTEST_SETTER(
         CTEST_INFO(
            "Checking if \"mbedtls_test->aArray\" at (%p) has fist %lu bytes filled with zeroes",
            mbedtls_test->aArray, ARRAY_SIZE-1
         ),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   err=mbedtls_mpi_write_binary(&mbedtls_test->B, (unsigned char *)mbedtls_test->bArray, sizeof(mbedtls_test->bArray));

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Wrinting B value to array B at pointer (%p) of size %lu", mbedtls_test->bArray, sizeof(mbedtls_test->bArray)),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d for mbedtls_mpi_write_binary when write B value", ERROR_SUCCESS, err),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   tmp=(mbedtls_mpi_sint)mbedtls_test->bArray[ARRAY_SIZE-1];

   C_ASSERT_TRUE(tmp==B_VALUE,
      CTEST_SETTER(
         CTEST_INFO(
            "Checking if \"mbedtls_test->bArray[ARRAY_SIZE-1]\" = %d is equal to B_VALUE = %d",
            tmp, B_VALUE
         ),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   C_ASSERT_TRUE(is_filled_with_value(mbedtls_test->bArray, ARRAY_SIZE-1, 0),
      CTEST_SETTER(
         CTEST_INFO(
            "Checking if \"mbedtls_test->bArray\" at (%p) has fist %lu bytes filled with zeroes",
            mbedtls_test->bArray, ARRAY_SIZE-1
         ),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   err=mbedtls_mpi_write_binary(&mbedtls_test->X, (unsigned char *)mbedtls_test->xArray, sizeof(mbedtls_test->xArray));

   C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
      CTEST_SETTER(
         CTEST_INFO("Wrinting X value to array X at pointer (%p) of size %lu", mbedtls_test->xArray, sizeof(mbedtls_test->xArray)),
         CTEST_ON_ERROR("Was expected error ERROR_SUCCESS (%d). But found %d for mbedtls_mpi_write_binary when write X value", ERROR_SUCCESS, err),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   tmp=(mbedtls_mpi_sint)mbedtls_test->xArray[ARRAY_SIZE-2];

   #define X_VALUE_MSB (mbedtls_mpi_sint)0x01
   #define X_VALUE_LSB (mbedtls_mpi_sint)0xEE

   C_ASSERT_TRUE(tmp==X_VALUE_MSB,
      CTEST_SETTER(
         CTEST_INFO(
            "Checking if \"mbedtls_test->aArray[ARRAY_SIZE-2]\" = %d is equal to X_VALUE_MSB = %d",
            tmp, X_VALUE_MSB
         ),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   tmp=(mbedtls_mpi_sint)mbedtls_test->xArray[ARRAY_SIZE-1];

   C_ASSERT_TRUE(tmp==X_VALUE_LSB,
      CTEST_SETTER(
         CTEST_INFO(
            "Checking if \"mbedtls_test->aArray[ARRAY_SIZE-1]\" = %d is equal to X_VALUE_LSB = %d",
            tmp, X_VALUE_LSB
         ),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   C_ASSERT_TRUE(is_filled_with_value(mbedtls_test->xArray, ARRAY_SIZE-2, 0),
      CTEST_SETTER(
         CTEST_INFO(
            "Checking if \"mbedtls_test->xArray\" at (%p) has fist %lu bytes filled with zeroes",
            mbedtls_test->xArray, ARRAY_SIZE-2
         ),
         CTEST_ON_ERROR_CB(nano_embedded_mbedtls_free_test, (void *)mbedtls_test)
      )
   )

   mbedtls_mpi_free(&mbedtls_test->B);
   mbedtls_mpi_free(&mbedtls_test->A);
   mbedtls_mpi_free(&mbedtls_test->X);

   free(mbedtls_test);

   #undef X_VALUE_LSB
   #undef X_VALUE_MSB
   #undef INITIAL_BYTE
   #undef MBEDTLS_TEST_SIZE
   #undef ARRAY_SIZE
}

static void free_mpi_size_test(void *ctx)
{
   mbedtls_ecdsa_context *ecdsa_ctx = (mbedtls_ecdsa_context *)ctx;

   printf("\nFreeing ecdsa_ctx at (%p) ...\n", ecdsa_ctx); 
   mbedtls_ecdsa_free(ecdsa_ctx);
   free(ecdsa_ctx);
}

struct test_ecdsa_t {
   int expected;
   size_t size;
   mbedtls_ecp_group_id gid;
   const char *gid_name;
} test_ecdsa[] = {
   {
      MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE,
      0,
      MBEDTLS_ECP_DP_NONE,
      "MBEDTLS_ECP_DP_NONE"
   },
   {
      ERROR_SUCCESS,
      32,
      MBEDTLS_ECP_DP_BP256R1,
      "MBEDTLS_ECP_DP_BP256R1"
   },
   {
      ERROR_SUCCESS,
      28,
      MBEDTLS_ECP_DP_SECP224R1,
      "MBEDTLS_ECP_DP_SECP224R1"
   },
   {
      ERROR_SUCCESS,
      32,
      MBEDTLS_ECP_DP_SECP256R1,
      "MBEDTLS_ECP_DP_SECP256R1"
   },
   {
      ERROR_SUCCESS,
      48,
      MBEDTLS_ECP_DP_SECP384R1,
      "MBEDTLS_ECP_DP_SECP384R1"
   },
   {
      ERROR_SUCCESS,
      66, // TODO Find why size is 66 instead 64
      MBEDTLS_ECP_DP_SECP521R1,
      "MBEDTLS_ECP_DP_SECP521R1"
   },
   {
      ERROR_SUCCESS,
      32,
      MBEDTLS_ECP_DP_BP256R1,
      "MBEDTLS_ECP_DP_BP256R1"
   },
   {
      ERROR_SUCCESS,
      48,
      MBEDTLS_ECP_DP_BP384R1,
      "MBEDTLS_ECP_DP_BP384R1"
   },
   {
      ERROR_SUCCESS,
      64,
      MBEDTLS_ECP_DP_BP512R1,
      "MBEDTLS_ECP_DP_BP512R1"
   },
   {
      ERROR_SUCCESS,
      32,
      MBEDTLS_ECP_DP_CURVE25519,
      "MBEDTLS_ECP_DP_CURVE25519"
   },
   {
      ERROR_SUCCESS,
      24,
      MBEDTLS_ECP_DP_SECP192K1,
      "MBEDTLS_ECP_DP_SECP192K1"
   },
   {
      ERROR_SUCCESS,
      28,
      MBEDTLS_ECP_DP_SECP224K1,
      "MBEDTLS_ECP_DP_SECP224K1"
   },
   {
      ERROR_SUCCESS,
      32,
      MBEDTLS_ECP_DP_SECP256K1,
      "MBEDTLS_ECP_DP_SECP256K1"
   },
   {
      ERROR_SUCCESS,
      56,
      MBEDTLS_ECP_DP_CURVE448,
      "MBEDTLS_ECP_DP_CURVE448"
   }
};

#define TEST_ECDSA_SZ sizeof(test_ecdsa)/sizeof(struct test_ecdsa_t)

void check_mbedTLS_mpi_size_test()
{
   int err;
   size_t sz;
   mbedtls_ecdsa_context *ecdsa_ctx;

   #define SUCCESS_ECDSA_MESSAGE "Success: Expected size = %lu for %s"
   #define ERROR_ECDSA_MESSAGE "Success: Expected size = %lu for %s but found %lu"

   ecdsa_ctx=malloc(sizeof(mbedtls_ecdsa_context));

   C_ASSERT_NOT_NULL(ecdsa_ctx,
      CTEST_SETTER(
         CTEST_INFO("Testing pointer for test \"ecdsa_ctx\"(%p) of size = %lu", ecdsa_ctx, sizeof(mbedtls_ecdsa_context))
      )
   )

   mbedtls_ecdsa_init(ecdsa_ctx);

   for (size_t i=0;i<TEST_ECDSA_SZ;i++) {
      INFO_MSG_FMT("Testing \"%s\". Index %u of %u", test_ecdsa[i].gid_name, i+1, TEST_ECDSA_SZ)

      err=mbedtls_ecp_group_load(&ecdsa_ctx->grp, test_ecdsa[i].gid);

      C_ASSERT_EQUAL_INT(test_ecdsa[i].expected, err,
         CTEST_SETTER(
            CTEST_ON_SUCCESS("Success on load %s ...", test_ecdsa[i].gid_name),
            CTEST_ON_ERROR("Error on load %s. Expected error number %d but found", test_ecdsa[i].gid_name, test_ecdsa[i].expected, err),
            CTEST_ON_ERROR_CB(free_mpi_size_test, (void *)ecdsa_ctx)
         )
      )

      sz=mbedtls_mpi_size(&ecdsa_ctx->grp.P);

      //TODO implement C_ASSERT_EQUAL_SIZE_T
      C_ASSERT_EQUAL_U64((uint64_t)test_ecdsa[i].size, (uint64_t)sz,
         CTEST_SETTER(
            CTEST_ON_SUCCESS(SUCCESS_ECDSA_MESSAGE, sz, test_ecdsa[i].gid_name),
            CTEST_ON_ERROR(ERROR_ECDSA_MESSAGE, test_ecdsa[i].size, test_ecdsa[i].gid_name, sz),
            CTEST_ON_ERROR_CB(free_mpi_size_test, (void *)ecdsa_ctx)
         )
      )
   }

   free_mpi_size_test(ecdsa_ctx);
   #undef ERROR_ECDSA_MESSAGE
   #undef SUCCESS_ECDSA_MESSAGE
}

static int rand_test(void *v, unsigned char *c, size_t c_sz)
{

   if (!c_sz)
      return -1;
   
   gen_rand_no_entropy(c, c_sz);
   printf(
      "Generating random number for %s of size %lu random\"%s\"\n",
      (char *)v, c_sz, fhex2strv2(msgbuf(), (const void *)c, c_sz, 0)
   );
   return 0;
}

void check_ec_secret_key_valid_test()
{
   #define RANDOM_SECRET_KEY (size_t)40
   int err, expected_err1, expected_err2;
   unsigned char sk[MBEDTLS_ECDSA_MAX_LEN+1];
   struct test_ecdsa_t tst;
   f_ecdsa_key_pair f_key_pair;

   f_key_pair.ctx=NULL;

   for (size_t k=1;k<TEST_ECDSA_SZ;k++) {

      tst=test_ecdsa[k];

      INFO_MSG_FMT("For k = %lu Checking secret keys for %s curve ...", k, tst.gid_name)

      
      expected_err1=ERR_SK_CHECK;
      expected_err2=expected_err1;
   
      switch (tst.gid)
      {
         case MBEDTLS_ECP_DP_SECP224K1:
            expected_err1=ERROR_SUCCESS;

         default:
            break;
      }

      err=f_ecdsa_secret_key_valid(tst.gid, memset(sk, 0xff, tst.size), tst.size);

      C_ASSERT_EQUAL_INT(expected_err1, err)

      err=f_ecdsa_secret_key_valid(tst.gid, memset(sk, 0x00, tst.size), tst.size);

      C_ASSERT_EQUAL_INT(expected_err2, err)

      err=f_ecdsa_secret_key_valid(tst.gid, memset(sk, 0x01, tst.size), tst.size);

      C_ASSERT_EQUAL_INT(
         ((tst.gid!=MBEDTLS_ECP_DP_CURVE25519)&&(tst.gid!=MBEDTLS_ECP_DP_CURVE448))?
         ERROR_SUCCESS:ERR_SK_CHECK,
         err
      )

      err=f_ecdsa_secret_key_valid(tst.gid, sk, tst.size+1);

      C_ASSERT_EQUAL_INT(ERR_KEY_WRONG_SIZE, err)

      err=f_ecdsa_secret_key_valid(tst.gid, sk, tst.size-1);

      C_ASSERT_EQUAL_INT(ERR_KEY_WRONG_SIZE, err)

      INFO_MSG_FMT("For k = %lu Checking random secret keys for %s curve...", k, tst.gid_name)

      for (size_t i=0; i<RANDOM_SECRET_KEY; i++) {

         INFO_MSG_FMT(
            "Generating private key for %s curve ... (%lu of %lu)",
            tst.gid_name,
            i,
            RANDOM_SECRET_KEY-1
         )

         f_key_pair.gid=tst.gid;       

         if ((err=f_gen_ecdsa_key_pair(&f_key_pair, MBEDTLS_ECP_PF_UNCOMPRESSED, rand_test, (void *)tst.gid_name))==MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE) {
            WARN_MSG_FMT("Generate curve for %s not available. Skipping ...", tst.gid_name)
            continue;
         }

         C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
            CTEST_SETTER(
               CTEST_ON_ERROR(
                  "f_gen_ecdsa_key_pair(). Was expected ERROR_SUCCESS(%d) but found %d for curve %s",
                  ERROR_SUCCESS, err, tst.gid_name
               )
            )
         )

         INFO_MSG_FMT(
            "Testing if secret key \"%s\" is valid (%lu of %lu) for %s curve. Key size %lu",
            fhex2strv2(msgbuf(), (const void *)f_key_pair.private_key, f_key_pair.private_key_sz, 1),
            i,
            RANDOM_SECRET_KEY-1,
            tst.gid_name,
            f_key_pair.private_key_sz
         )

         err=f_ecdsa_secret_key_valid(tst.gid, f_key_pair.private_key, f_key_pair.private_key_sz);
         C_ASSERT_EQUAL_INT(ERROR_SUCCESS, err,
            CTEST_SETTER(
               CTEST_ON_ERROR(
                  "check_ec_secret_key_valid_test(). Was expected ERROR_SUCCESS(%d) but found %d for sk = \"%s\"",
                  ERROR_SUCCESS, err, msgbuf()
               )
            )
         )
      }
   }
   #undef TEST_ECDSA_SZ
   #undef RANDOM_SECRET_KEY
}
