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

