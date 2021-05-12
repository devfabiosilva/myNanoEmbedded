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

