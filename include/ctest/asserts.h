#include <stdint.h>

#define C_TEST_TRUE (int)(1==1)
#define C_TEST_FALSE (int)(1!=1)

void _c_test_ignore();
void _c_test_ignore_end();

#define C_TEST_BEGIN_IGNORE _c_test_ignore();
#define C_TEST_END_IGNORE _c_test_ignore_end();

#define END_TITLE "\e[0m"
#define INITIAL_TITLE "\e[1;3m"
#define ERROR_CODE "\e[31;1m"
#define SUCCESS_CODE "\e[32;1m"
#define WARNING_CODE "\e[33;1m"
#define INFO_CODE "\e[34;1m"

void write_title(const char *, const char *);
void write_title_fmt(const char *, const char *, ...);

#define TITLE_MSG(msg) write_title(msg, INITIAL_TITLE);
#define ERROR_MSG(msg) write_title(msg, ERROR_CODE);
#define SUCCESS_MSG(msg) write_title(msg, SUCCESS_CODE);
#define WARN_MSG(msg) write_title(msg, WARNING_CODE);
#define INFO_MSG(msg) write_title(msg, INFO_CODE);

#define TITLE_MSG_FMT(...) write_title_fmt(INITIAL_TITLE, __VA_ARGS__);
#define ERROR_MSG_FMT(...) write_title_fmt(ERROR_CODE, __VA_ARGS__);
#define WARN_MSG_FMT(...) write_title_fmt(WARNING_CODE, __VA_ARGS__);
#define INFO_MSG_FMT(...) write_title_fmt(INFO_CODE, __VA_ARGS__);
#define SUCCESS_MSG_FMT(...) write_title_fmt(SUCCESS_CODE, __VA_ARGS__);

uint64_t *get_va_end_signature();
uint64_t *get_vas_end_signature();

#define VA_END_SIGNATURE get_va_end_signature()
#define VAS_END_SIGNATURE get_vas_end_signature()

typedef void (*header_on_cb)(void *);
typedef void (*cb_fn)(void *);

void *set_varg_callback(uint32_t, cb_fn, ...);

void assert_true(int, ...);
void assert_false(int, ...);
void assert_equal_int(int, int, ...);
void assert_not_equal_int(int, int, ...);
void assert_equal_longint(long long int, long long int, ...);
void assert_not_equal_longint(long long int, long long int, ...);
void assert_equal_double(double, double, double, ...);
void assert_not_equal_double(double, double, double, ...);
void assert_equal_byte(
   void *,
   void *,
   size_t,
   ...
);
void assert_not_equal_byte(
   void *,
   void *,
   size_t,
   ...
);
void assert_equal_string(const char *, const char *, ...);
void assert_not_equal_string(const char *, const char *, ...);
void assert_equal_string_ignore_case(const char *, const char *, ...);
void assert_not_equal_string_ignore_case(const char *, const char *, ...);
void assert_null(void *, ...);
void assert_not_null(void *, ...);
void on_add_test(header_on_cb);
void rm_on_add_test();
void on_begin_test(header_on_cb);
void rm_begin_test();
void on_test(header_on_cb);
void rm_on_test();
void on_end_test(header_on_cb);
void rm_on_end_test();
void on_abort(header_on_cb);
void rm_on_abort();
void end_tests();
void *vargs_setter(int, ...);
void *set_varg(uint32_t, const char *, ...);

#define C_TEST_TYPE_VARGS_MSG (uint32_t)(0x10000000)
#define C_TEST_TYPE_VARGS_CALLBACK (uint32_t)(0x20000000|C_TEST_TYPE_VARGS_MSG)

#define C_TEST_VARGS_TITLE (uint32_t)(C_TEST_TYPE_VARGS_MSG|0x002E4992)
#define C_TEST_VARGS_INFO (uint32_t)(C_TEST_TYPE_VARGS_MSG|0x012E4992)
#define C_TEST_VARGS_WARNING (uint32_t)(C_TEST_TYPE_VARGS_MSG|0x022E4992)
#define C_TEST_VARGS_ERROR (uint32_t)(C_TEST_TYPE_VARGS_MSG|0x032E4992)
#define C_TEST_VARGS_SUCCESS (uint32_t)(C_TEST_TYPE_VARGS_MSG|0x042E4992)

#define C_TEST_VARGS_ON_SUCCESS_CALLBACK (uint32_t)(C_TEST_TYPE_VARGS_CALLBACK|0x052E4992)
#define C_TEST_VARGS_ON_ERROR_CALLBACK (uint32_t)(C_TEST_TYPE_VARGS_CALLBACK|0x062E4992)

#define CTEST_SETTER(...) vargs_setter(-1, __VA_ARGS__, NULL, VA_END_SIGNATURE)

#define CTEST_TITLE(...) set_varg(C_TEST_VARGS_TITLE, __VA_ARGS__)
#define CTEST_INFO(...) set_varg(C_TEST_VARGS_INFO, __VA_ARGS__)
#define CTEST_WARN(...) set_varg(C_TEST_VARGS_WARNING, __VA_ARGS__)
#define CTEST_ON_ERROR(...) set_varg(C_TEST_VARGS_ERROR, __VA_ARGS__)
#define CTEST_ON_SUCCESS(...) set_varg(C_TEST_VARGS_SUCCESS, __VA_ARGS__)
#define CTEST_ON_SUCCESS_CB(...) set_varg_callback(C_TEST_VARGS_ON_SUCCESS_CALLBACK, __VA_ARGS__, NULL, VAS_END_SIGNATURE)
#define CTEST_ON_ERROR_CB(...) set_varg_callback(C_TEST_VARGS_ON_ERROR_CALLBACK, __VA_ARGS__, NULL, VAS_END_SIGNATURE)

#define C_ASSERT_FALSE(...) assert_false(__VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_TRUE(...) assert_true(__VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_EQUAL_INT(expected, ...) assert_equal_int(expected, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_NOT_EQUAL_INT(expected, ...) assert_not_equal_int(expected, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_EQUAL_LONG_INT(expected, ...) assert_equal_longint(expected, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_NOT_EQUAL_LONG_INT(expected, ...) assert_not_equal_longint(expected, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_EQUAL_DOUBLE(expected, result, ...) assert_equal_double(expected, result, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_NOT_EQUAL_DOUBLE(expected, result, ...) assert_not_equal_double(expected, result, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_EQUAL_BYTE(expected, result, ...) assert_equal_byte(expected, result, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_NOT_EQUAL_BYTE(expected, result, ...) assert_not_equal_byte(expected, result, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_NULL(...) assert_null(__VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_NOT_NULL(...) assert_not_null(__VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_EQUAL_STRING(expected, ...) assert_equal_string(expected, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_NOT_EQUAL_STRING(expected, ...) assert_not_equal_string(expected, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_EQUAL_STRING_IGNORE_CASE(expected, ...) assert_equal_string_ignore_case(expected, __VA_ARGS__, VAS_END_SIGNATURE);
#define C_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE(expected, ...) assert_not_equal_string_ignore_case(expected, __VA_ARGS__, VAS_END_SIGNATURE);
#ifdef DEBUG_TEST
// TEMPORARY FOR TESTS

 int load_test_vargs_for_test(void **, ...);
 int load_test_vargs_for_test_v2(void **, ...);
 int free_vargs_for_test(void *);
 char *ctest_setter_has_title(void *);
 char *ctest_setter_has_info(void *);
 char *ctest_setter_has_warn(void *);
 char *ctest_setter_has_onerror(void *);
 char *ctest_setter_has_onsuccess(void *);
 void show_message_text();
#endif

