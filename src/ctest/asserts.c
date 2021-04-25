//Fri abr 02 20:42:11 -03 2021
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <asserts.h>
#include <time.h>
#include <math.h>

static void print_assert_int(void *, void *);
static void print_assert_longint(void *, void *);
static void print_assert_byte(void *, void *);
static void print_assert_double(void *, void *);
static void print_assert_string(void *, void *);
static void print_assert_nullable(void *, void *);

static void abort_tests();

/*
static void debug_hex_dump(unsigned char *data, size_t data_size)
{
   if (!data) {
      printf("\nWARNING: NULL pointer. Aborting\n");
      return;
   }
   if (!data_size)
      return;

   for (;data_size--;)
      printf("%02X ", (unsigned char)*(data++));
}
*/
#define END_TITLE "\e[0m"
#define INITIAL_TITLE "\e[1;3m"
#define ERROR_CODE "\e[31;1m"
#define SUCCESS_CODE "\e[32;1m"
#define WARNING_CODE "\e[33;1m"
#define INFO_CODE "\e[34;1m"

#define C_TEST_TRUE (int)(1==1)
#define C_TEST_FALSE (int)(1!=1)

_Static_assert(C_TEST_TRUE==1, "Compiler should return 1 for TRUE");
_Static_assert(C_TEST_FALSE==0, "Compiler should return 0 for FALSE");

#define C_TEST_HEADER_SIGNATURE (uint32_t)(0x0012E4992)

void *_c_test_ptr=NULL;

typedef void (*header_on_cb)(void *);

typedef struct c_test_header {
   uint32_t signature;

   size_t
   tests,
   next;

   uint64_t
   initial_timestamp,
   final_timestamp;

   header_on_cb
   on_add_test_fn,
   on_test_fn,
   on_begin_test_fn,
   on_end_test_fn,
   on_abort_fn;

} C_TEST_HEADER;

typedef struct c_test_fn_description {
   uint32_t type;
   const char *fn_name;
   size_t blk_size;
   void (*cb)(void *, void *);
} C_TEST_FN_DESCRIPTION;

typedef C_TEST_FN_DESCRIPTION C_TEST_FN_META;

typedef struct c_test_type_header_t {
   C_TEST_FN_DESCRIPTION desc;

   const char
   *on_error, // TODO Remove
   *on_success, // TODO Remove
   *on_warning; // TODO Remove

} C_TEST_TYPE_HEADER;

typedef struct c_test_type_int_t {
   C_TEST_TYPE_HEADER header;

   int
   expected,
   result;
} C_TEST_TYPE_INT, C_TEST_TYPE_BOOL;

typedef struct c_test_type_long_int_t {
   C_TEST_TYPE_HEADER header;

   long long int
   expected,
   result;
} C_TEST_TYPE_LONG_INT;

typedef struct c_test_type_double_t {
   C_TEST_TYPE_HEADER header;
/*
   int
   is_not_equal;
*/
   double
   expected,
   result,
   delta;
} C_TEST_TYPE_DOUBLE;

typedef struct c_test_type_byte_t {
   C_TEST_TYPE_HEADER header;

   void
   *expected,
   *result,
   *free_on_error_ctx; // TODO Remove 

   size_t size;

   free_on_error_fn
   free_on_error_cb; // TODO Remove
} C_TEST_TYPE_BYTE;

typedef struct c_test_type_string_t {
   C_TEST_TYPE_HEADER header;

   const char
   *expected,
   *result;
} C_TEST_TYPE_STRING;

typedef struct c_test_type_nullable_t {
   C_TEST_TYPE_HEADER header;
/*
   int
   should_be_null;
*/
   void
   *pointer,
   *free_on_error_ctx;

   free_on_error_fn
   free_on_error_cb;
} C_TEST_TYPE_NULLABLE;

#define C_TEST_VARGS_SETTER (uint32_t)(0x043E4992)
#define C_TEST_VARGS_SETTER_CHK_SUM (uint32_t)(0x1bc1eeb8)

const uint32_t C_TEST_VARGS_MSG_SIGS[] = {
   C_TEST_VARGS_TITLE, C_TEST_VARGS_INFO, C_TEST_VARGS_WARNING,
   C_TEST_VARGS_ERROR, C_TEST_VARGS_SUCCESS
};

#define C_TEST_VARGS_MSG_SIGS_SIZE (sizeof(C_TEST_VARGS_MSG_SIGS)/sizeof(uint32_t))

typedef struct c_test_vargs_msg_t {
   uint32_t sig;
   int msg_sz;
   char *msg;
} C_TEST_VARGS_MSG;

typedef struct c_test_vargs_msg_header_t {
   uint32_t sig;
   uint32_t sig_chk;
   C_TEST_VARGS_MSG *vargs_msgs[C_TEST_VARGS_MSG_SIGS_SIZE+1];
} C_TEST_VARGS_MSG_HEADER;

static C_TEST_VARGS_MSG *check_vargs_sigmsg_exists(C_TEST_VARGS_MSG **, uint32_t);

#define ASSERT_EQ_INT_FN "assert_equal_int"
#define ASSERT_TRUE_FN "assert_true"
#define ASSERT_FALSE_FN "assert_false"
#define ASSERT_EQUAL_LONG_INT "assert_equal_longint"
#define ASSERT_EQUAL_DOUBLE "assert_equal_double"
#define ASSERT_EQUAL_BYTE "assert_equal_byte"
#define ASSERT_NOT_EQUAL_INT_FN "assert_not_equal"
#define ASSERT_NOT_EQUAL_LONG_INT "assert_not_equal_longint"
#define ASSERT_NOT_EQUAL_DOUBLE "assert_not_equal_double"
#define ASSERT_NOT_EQUAL_BYTE "assert_not_equal_byte"
#define ASSERT_EQUAL_STRING "assert_equal_string"
#define ASSERT_NOT_EQUAL_STRING "assert_not_equal_string"
#define ASSERT_EQUAL_STRING_IGNORE_CASE "assert_equal_string_ignore_case"
#define ASSERT_NOT_EQUAL_STRING_IGNORE_CASE "assert_not_equal_string_ignore_case"
#define ASSERT_NULL "assert_null"
#define ASSERT_NOT_NULL "assert_not_null"

#define TYPE_ASSERT_EQUAL_INT 0
#define TYPE_ASSERT_TRUE 1
#define TYPE_ASSERT_FALSE 2
#define TYPE_ASSERT_EQUAL_LONG_INT 3
#define TYPE_ASSERT_EQUAL_DOUBLE 4
#define TYPE_ASSERT_EQUAL_BYTE 5
#define TYPE_ASSERT_NOT_EQUAL_INT 6
#define TYPE_TYPE_ASSERT_NOT_EQUAL_LONG_INT 7
#define TYPE_ASSERT_NOT_EQUAL_DOUBLE 8
#define TYPE_ASSERT_NOT_EQUAL_BYTE 9
#define TYPE_ASSERT_EQUAL_STRING 10
#define TYPE_ASSERT_NOT_EQUAL_STRING 11
#define TYPE_ASSERT_EQUAL_STRING_IGNORE_CASE 12
#define TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE 13
#define TYPE_ASSERT_NULL 14
#define TYPE_ASSERT_NOT_NULL 15
static C_TEST_FN_DESCRIPTION _tst_fn_desc[] = {
   {TYPE_ASSERT_EQUAL_INT, ASSERT_EQ_INT_FN, sizeof(C_TEST_TYPE_INT), print_assert_int},
   {TYPE_ASSERT_TRUE, ASSERT_TRUE_FN, sizeof(C_TEST_TYPE_BOOL), print_assert_int},
   {TYPE_ASSERT_FALSE, ASSERT_FALSE_FN, sizeof(C_TEST_TYPE_BOOL), print_assert_int},
   {TYPE_ASSERT_EQUAL_LONG_INT, ASSERT_EQUAL_LONG_INT, sizeof(C_TEST_TYPE_LONG_INT), print_assert_longint},
   {TYPE_ASSERT_EQUAL_DOUBLE, ASSERT_EQUAL_DOUBLE, sizeof(C_TEST_TYPE_DOUBLE), print_assert_double},
   {TYPE_ASSERT_EQUAL_BYTE, ASSERT_EQUAL_BYTE, sizeof(C_TEST_TYPE_BYTE), print_assert_byte},
   {TYPE_ASSERT_NOT_EQUAL_INT, ASSERT_NOT_EQUAL_INT_FN, sizeof(C_TEST_TYPE_INT), print_assert_int},
   {TYPE_TYPE_ASSERT_NOT_EQUAL_LONG_INT, ASSERT_NOT_EQUAL_LONG_INT, sizeof(C_TEST_TYPE_LONG_INT), print_assert_longint},
   {TYPE_ASSERT_NOT_EQUAL_DOUBLE, ASSERT_NOT_EQUAL_DOUBLE, sizeof(C_TEST_TYPE_DOUBLE), print_assert_double},
   {TYPE_ASSERT_NOT_EQUAL_BYTE, ASSERT_NOT_EQUAL_BYTE, sizeof(C_TEST_TYPE_BYTE), print_assert_byte},
   {TYPE_ASSERT_EQUAL_STRING, ASSERT_EQUAL_STRING, sizeof(C_TEST_TYPE_STRING), print_assert_string},
   {TYPE_ASSERT_NOT_EQUAL_STRING, ASSERT_NOT_EQUAL_STRING, sizeof(C_TEST_TYPE_STRING), print_assert_string},
   {TYPE_ASSERT_EQUAL_STRING_IGNORE_CASE, ASSERT_EQUAL_STRING_IGNORE_CASE, sizeof(C_TEST_TYPE_STRING), print_assert_string},
   {TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE, ASSERT_NOT_EQUAL_STRING_IGNORE_CASE, sizeof(C_TEST_TYPE_STRING), print_assert_string},
   {TYPE_ASSERT_NULL, ASSERT_NULL, sizeof(C_TEST_TYPE_NULLABLE), print_assert_nullable},
   {TYPE_ASSERT_NOT_NULL, ASSERT_NOT_NULL, sizeof(C_TEST_TYPE_NULLABLE), print_assert_nullable}
};

#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_INT _tst_fn_desc[TYPE_ASSERT_EQUAL_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_TRUE _tst_fn_desc[TYPE_ASSERT_TRUE]
#define C_TEST_FN_DESCRIPTION_ASSERT_FALSE _tst_fn_desc[TYPE_ASSERT_FALSE]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_LONG_INT _tst_fn_desc[TYPE_ASSERT_EQUAL_LONG_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_DOUBLE _tst_fn_desc[TYPE_ASSERT_EQUAL_DOUBLE]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_BYTE _tst_fn_desc[TYPE_ASSERT_EQUAL_BYTE]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_INT _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_LONG_INT _tst_fn_desc[TYPE_TYPE_ASSERT_NOT_EQUAL_LONG_INT]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_DOUBLE _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_DOUBLE]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_BYTE _tst_fn_desc[TYPE_ASSERT_NOT_EQUAL_BYTE]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_STRING _tst_fn_desc[10]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_STRING _tst_fn_desc[11]
#define C_TEST_FN_DESCRIPTION_ASSERT_EQ_STRING_IGNORE_CASE _tst_fn_desc[12]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_STRING_IGNORE_CASE _tst_fn_desc[13]
#define C_TEST_FN_DESCRIPTION_ASSERT_NULL _tst_fn_desc[TYPE_ASSERT_NULL]
#define C_TEST_FN_DESCRIPTION_ASSERT_NOT_NULL _tst_fn_desc[TYPE_ASSERT_NOT_NULL]

typedef union c_test_fn {
   C_TEST_FN_META meta;
   C_TEST_TYPE_INT tst_eq_int;
   C_TEST_TYPE_BOOL tst_eq_bool;
   C_TEST_TYPE_LONG_INT tst_eq_longint;
   C_TEST_TYPE_DOUBLE tst_eq_double;
   C_TEST_TYPE_BYTE tst_eq_byte;
   C_TEST_TYPE_STRING tst_eq_string;
   C_TEST_TYPE_NULLABLE tst_eq_null;
} C_TEST_FN;

#define PRINTF_FINAL_FMT printf("%.*s", err, msg);
static void write_title(const char *message, const char *template)
{
   int err;
   char *msg;

   if (!message) {
      printf("Missing message");
      abort_tests();
   }

   if ((err=asprintf(&msg, "%s%s%s\n", template, message, END_TITLE))<0) {
      printf("Message error");
      abort_tests();
   }

   PRINTF_FINAL_FMT

   free(msg);
}

static void write_title_fmt(const char *template, const char *fmt, ...)
{
   int err;
   char *msg_fmt, *msg;
   va_list args;

   if (!fmt) {
      printf("Missing format at \"write_title_fmt\"");
      abort_tests();
   }

   va_start(args, fmt);
   err=vasprintf(&msg_fmt, fmt, args);
   va_end(args);

   if (err<0) {
      printf("Message format error at \"write_title_fmt\"");
      free(msg_fmt);
      abort_tests();
   }

   err=asprintf(&msg, "%s%.*s%s\n", template, err, msg_fmt, END_TITLE);

   free(msg_fmt);

   if (err<0) {
      printf("Final message error at \"write_title_fmt\"");
      abort_tests();
   }

   PRINTF_FINAL_FMT

   free(msg);
}

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

static void end_tests_util(int abort)
{
   time_t t;

   if (_c_test_ptr) {
      t=time(NULL);

      if (abort) {
         if (((C_TEST_HEADER *)_c_test_ptr)->on_abort_fn)
            ((C_TEST_HEADER *)_c_test_ptr)->on_abort_fn(_c_test_ptr);

         ERROR_MSG_FMT("Aborting TESTS.\nAt %s\nTests: %d finished", ctime(&t), ((C_TEST_HEADER *)_c_test_ptr)->next)
      } else {
         if (((C_TEST_HEADER *)_c_test_ptr)->on_end_test_fn)
            ((C_TEST_HEADER *)_c_test_ptr)->on_end_test_fn(_c_test_ptr);

         TITLE_MSG_FMT("*** END TESTS ***\nTotal: %d\nAt: %s", ((C_TEST_HEADER *)_c_test_ptr)->tests, ctime(&t))
         TITLE_MSG_FMT("Total time: %llu\n", (uint64_t)t-((C_TEST_HEADER *)_c_test_ptr)->initial_timestamp)
      }

      if (((C_TEST_HEADER *)_c_test_ptr)->tests)
         memset(_c_test_ptr+sizeof(C_TEST_HEADER), 0, (((C_TEST_HEADER *)_c_test_ptr)->tests)*sizeof(C_TEST_FN));

      memset(_c_test_ptr, 0, sizeof(C_TEST_HEADER));
      free(_c_test_ptr);
      _c_test_ptr=NULL;

   } else if (abort)
      ERROR_MSG("\nERROR: Null pointer. Probably you start ctest with invalid argument. Aborting C test.\n")
   else
      WARN_MSG("\nWARNING: Null pointer. Probably you start ctest with invalid argument. Ignoring ...\n")
}

void end_tests() { end_tests_util(0); }

static void abort_tests() {
   end_tests_util(1);
   exit(1);
}

static void begin_test(void *vas)
{
   C_TEST_FN *p, *q;
   time_t t;

   p=((C_TEST_FN *)(_c_test_ptr+sizeof(C_TEST_HEADER)));

   t=time(NULL);

   if (!((C_TEST_HEADER *)_c_test_ptr)->next) {
      ((C_TEST_HEADER *)_c_test_ptr)->initial_timestamp=(uint64_t)t;
      TITLE_MSG_FMT("*** BEGIN TEST ***\nAt: %s", ctime(&t))

      if (((C_TEST_HEADER *)_c_test_ptr)->on_begin_test_fn)
         ((C_TEST_HEADER *)_c_test_ptr)->on_begin_test_fn(_c_test_ptr);

   }

   q=&p[((C_TEST_HEADER *)_c_test_ptr)->next++];
   TITLE_MSG_FMT("Testing %d -> \"%s\" (%p)...", ((C_TEST_HEADER *)_c_test_ptr)->next, q->meta.fn_name, q)
   q->meta.cb(q, vas);

   TITLE_MSG_FMT("Duration (ms): %llu\n", (uint64_t)time(NULL)-t)
}

#define C_TEST_INITIAL_ADD \
   ((C_TEST_HEADER *)p)->signature=C_TEST_HEADER_SIGNATURE;\
   ((C_TEST_HEADER *)p)->tests=0U;\
   ((C_TEST_HEADER *)p)->next=0U;\
   ((C_TEST_HEADER *)p)->initial_timestamp=0UL;\
   ((C_TEST_HEADER *)p)->final_timestamp=0UL;

#define C_TEST_ON_ADD_FN(fn) ((C_TEST_HEADER *)p)->on_add_test_fn=fn;
#define C_TEST_ON_TEST_FN(fn) ((C_TEST_HEADER *)p)->on_test_fn=fn;
#define C_TEST_ON_BEGIN_FN(fn) ((C_TEST_HEADER *)p)->on_begin_test_fn=fn;
#define C_TEST_ON_END_FN(fn) ((C_TEST_HEADER *)p)->on_end_test_fn=fn;
#define C_TEST_ON_ABORT_FN(fn) ((C_TEST_HEADER *)p)->on_abort_fn=fn;

#define C_TEST_ON_ADD_FN_POINTER ((C_TEST_HEADER *)p)->on_add_test_fn
#define C_TEST_ON_BEGIN_FN_POINTER ((C_TEST_HEADER *)p)->on_begin_test_fn
#define C_TEST_ON_TEST_FN_POINTER ((C_TEST_HEADER *)p)->on_test_fn
#define C_TEST_ON_END_FN_POINTER ((C_TEST_HEADER *)p)->on_end_test_fn
#define C_TEST_ON_ABORT_FN_POINTER ((C_TEST_HEADER *)p)->on_abort_fn

#define C_TEST_INITIAL_ADD_FN_ALL_NULL \
   C_TEST_ON_ADD_FN(NULL) \
   C_TEST_ON_TEST_FN(NULL) \
   C_TEST_ON_BEGIN_FN(NULL) \
   C_TEST_ON_END_FN(NULL) \
   C_TEST_ON_ABORT_FN(NULL)

#define ON_TEST_WARN1 "WARNING: %s callback already exists at pointer (%p). Overwriting with a new callback pointer (%p)"
#define ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(fn_name, ptr) \
   if (ptr) \
      WARN_MSG_FMT(ON_TEST_WARN1, fn_name, ptr, fn);

#define ON_ADD_TEST_STR "on_add_test()"
void on_add_test(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_add_test missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_add_test missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_BEGIN_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)
      C_TEST_ON_END_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_ADD_TEST_STR, C_TEST_ON_ADD_FN_POINTER)

   C_TEST_ON_ADD_FN(fn)

   #undef p
}

#define RM_ON_TEST_WARN1 "WARNING: %s without %s. Ignoring ..." 
#define RM_ON_TEST_WARN2 "WARNING: %s may be NOT initialized. Ignoring ..."
#define RM_ON_ADD_TEST_STR "rm_on_add_test()"
void rm_on_add_test()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_ADD_FN_POINTER)
         C_TEST_ON_ADD_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_ADD_TEST_STR, ON_ADD_TEST_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_ADD_TEST_STR)

   #undef p
}

#define ON_BEGIN_TEST_STR "on_begin_test()"
void on_begin_test(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_begin_test missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_begin_test missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_ADD_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)
      C_TEST_ON_END_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_BEGIN_TEST_STR, C_TEST_ON_BEGIN_FN_POINTER)

   C_TEST_ON_BEGIN_FN(fn)

   #undef p
}

#define RM_ON_BEGIN_TEST_STR "rm_begin_test()"
void rm_begin_test()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_BEGIN_FN_POINTER)
         C_TEST_ON_BEGIN_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_BEGIN_TEST_STR, ON_BEGIN_TEST_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_BEGIN_TEST_STR)

   #undef p
}

#define ON_TEST_STR "on_test()"
void on_test(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_test missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_test missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_ADD_FN(NULL)
      C_TEST_ON_BEGIN_FN(NULL)
      C_TEST_ON_END_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_TEST_STR, C_TEST_ON_TEST_FN_POINTER)

   C_TEST_ON_TEST_FN(fn)

   #undef p
}

#define RM_ON_TEST_TEST_STR "rm_on_test()"
void rm_on_test()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_TEST_FN_POINTER)
         C_TEST_ON_TEST_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_TEST_TEST_STR, ON_TEST_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_TEST_STR)

   #undef p
}

#define ON_END_TEST_STR "on_end_test()"
void on_end_test(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_end_test missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_end_test missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_ADD_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)
      C_TEST_ON_BEGIN_FN(NULL)
      C_TEST_ON_ABORT_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_END_TEST_STR, C_TEST_ON_END_FN_POINTER)

   C_TEST_ON_END_FN(fn)

   #undef p
}

#define RM_ON_END_TEST_STR "rm_on_end_test()"
void rm_on_end_test()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_END_FN_POINTER)
         C_TEST_ON_END_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_END_TEST_STR, ON_END_TEST_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_END_TEST_STR)

   #undef p
}

#define ON_ABORT_STR "on_abort()"
void on_abort(header_on_cb fn)
{
   #define p _c_test_ptr

   if (!fn) {
      ERROR_MSG("Fatal: on_abort missing callback function")
      abort_tests();
   }

   if (!p) {
      if (!(p=malloc(sizeof(C_TEST_HEADER)))) {
         ERROR_MSG("Fatal: on_abort missing callback function. Can't alloc memory")
         abort_tests();
      }

      C_TEST_INITIAL_ADD

      C_TEST_ON_ADD_FN(NULL)
      C_TEST_ON_TEST_FN(NULL)
      C_TEST_ON_BEGIN_FN(NULL)
      C_TEST_ON_END_FN(NULL)

   }

   ON_TEST_WARN1_IF_CALLBACK_ALREADY_EXISTS(ON_ABORT_STR, C_TEST_ON_ABORT_FN_POINTER)

   C_TEST_ON_ABORT_FN(fn)

   #undef p
}

#define RM_ON_ABORT_STR "rm_abort()"
void rm_abort()
{
   #define p _c_test_ptr

   if (p) {
      if (C_TEST_ON_ABORT_FN_POINTER)
         C_TEST_ON_ABORT_FN(NULL)
      else
         WARN_MSG_FMT(RM_ON_TEST_WARN1, RM_ON_ABORT_STR, ON_ABORT_STR)
   } else
      WARN_MSG_FMT(RM_ON_TEST_WARN2, ON_ABORT_STR)

   #undef p
}
//
// memory sanitizer check
_Static_assert(sizeof(int)>=sizeof(uint32_t), "Processor architecture should be 32 bit or more");
//
#define C_VARGS_SZ sizeof(C_TEST_VARGS_MSG_HEADER)
static inline int c_test_is_header_invalid(C_TEST_VARGS_MSG_HEADER *header)
{

   if (header->sig^C_TEST_VARGS_SETTER)
      return -2;

   if (header->sig_chk^C_TEST_VARGS_SETTER_CHK_SUM)
      return -3;

   return 0;
//   return ((header->sig^C_TEST_VARGS_SETTER)|(header->sig_chk^C_TEST_VARGS_SETTER_CHK_SUM)); // Memory sanity check
}

static C_TEST_VARGS_MSG_HEADER *c_test_vargs_create()
{
   void *c_vargs;

   if (!(c_vargs=malloc(C_VARGS_SZ)))
      return NULL;

   ((C_TEST_VARGS_MSG_HEADER *)c_vargs)->sig=C_TEST_VARGS_SETTER;
   ((C_TEST_VARGS_MSG_HEADER *)c_vargs)->sig_chk=C_TEST_VARGS_SETTER_CHK_SUM;
   memset(((C_TEST_VARGS_MSG_HEADER *)c_vargs)->vargs_msgs, 0, sizeof(C_TEST_VARGS_MSG *)*(C_TEST_VARGS_MSG_SIGS_SIZE+1));
   return (C_TEST_VARGS_MSG_HEADER *)c_vargs;
}

static C_TEST_VARGS_MSG *check_vargs_sigmsg_exists(C_TEST_VARGS_MSG **test_vargs_msg, uint32_t sig)
{
   C_TEST_VARGS_MSG **p;

   p=test_vargs_msg;

   for (;(*p);p++)
      if ((*p)->sig==sig)
         return (*p);

   return NULL;
}

static uint32_t check_msgsig(C_TEST_VARGS_MSG *va_msg)
{
   uint32_t i=0;

   if (!va_msg)
      return 0;

   for (;i<C_TEST_VARGS_MSG_SIGS_SIZE;)
      if (va_msg->sig==C_TEST_VARGS_MSG_SIGS[i++])
         return va_msg->sig;

   return 0;
}

static int free_vargs(void *vargs)
{
   int err;
   C_TEST_VARGS_MSG **p;

   if (!vargs)
      return 0;

   err=0;
   p=((C_TEST_VARGS_MSG_HEADER *)vargs)->vargs_msgs;

   while (*p) {
      if (!check_msgsig(*p)) {
         err=7;
         ERROR_MSG("ERROR: check_msgsig(). Missing or invalid message signature. Maybe wrong parameters. Ignoring free argument")
         continue;
      }

      if ((*p)->msg_sz>=0) {
         if ((*p)->msg)
            free((*p)->msg);
      } else
         ERROR_MSG_FMT("ERROR %d: free_vargs(). Error dealloc message. Signature = %04x at address = (%p)", (err=(*p)->msg_sz), (*p)->sig, (*p))

      free(*(p++));
   }

   free(memset(vargs, 0, C_VARGS_SZ));

   return err;
}

#define CLOSE_VARG_ERR_NULL (int)8
#define CLOSE_VARG_ERR_WRONG_SIG (int)9
static int close_varg(C_TEST_VARGS_MSG *varg)
{
   int err;

   if (!varg) {
      WARN_MSG("WARNING: close_varg() is NULL. Ignoring closing parameter")
      return CLOSE_VARG_ERR_NULL;
   }

   if (!check_msgsig(varg)) {
      WARN_MSG_FMT("WARNING: check_msgsig() @ close_varg. Signature not found in address (%p). Ignoring closing", (void *)varg)
      return CLOSE_VARG_ERR_WRONG_SIG;
   }

   err=0;

   if (varg->msg_sz>=0) {
      if (varg->msg)
         free(varg->msg);

   } else
      WARN_MSG_FMT(
         "WARNING %d: close_varg(). Message may be a wrong format at address (%p). Closing vargs...",
          err=varg->msg_sz, 
          (void *)varg
      )

   free(varg);

   return err;
}

void *set_varg(uint32_t sig, const char *message, ...)
{
   C_TEST_VARGS_MSG *varg_tmp;
   va_list args;

   if (!(varg_tmp=malloc(sizeof(C_TEST_VARGS_MSG))))
      return NULL;

   varg_tmp->sig=sig;
   va_start(args, message);
   varg_tmp->msg_sz=vasprintf(&varg_tmp->msg, message, args);
   va_end(args);

   return (void *)varg_tmp;
}

#define VARG_ERROR_MSG_NULL_PARM "ERROR: CTEST_SETTER has NULL parameter at argument %d."
#define VARG_ERROR_MSG_MANY_ARGUMENTS "ERROR: CTEST_SETTER has too many arguments"
void *vargs_setter(int initial, ...)
{
   int err, argc;
   void *v;
   va_list args, args_cpy;
   C_TEST_VARGS_MSG_HEADER *ret;
   C_TEST_VARGS_MSG **vargs_msgs;

   if (initial!=-1) {
      ERROR_MSG("ERROR: Initial value is wrong. Please consider use \"CTEST_SETTER\" instead. Ignoring parameter ...")
      return NULL;
   }

   err=0;
   argc=0;

   va_start(args, initial);
   va_copy(args_cpy, args);
#define MAX_ARG_OVF (size_t)C_TEST_VARGS_MSG_SIGS_SIZE+2
   while ((argc++)<(MAX_ARG_OVF+1)) {

      if (argc>MAX_ARG_OVF) {
         argc--;
         err=-3;
         ERROR_MSG(VARG_ERROR_MSG_MANY_ARGUMENTS)
         break;
      }

      if ((v=(void *)va_arg(args, void *))==VA_END_SIGNATURE)
         break;

      if (!v) {

         argc++;

         if (argc>MAX_ARG_OVF) {
            argc--;
            err=-5;
            ERROR_MSG(VARG_ERROR_MSG_MANY_ARGUMENTS)
            break;
         }

         if ((v=(void *)va_arg(args, void *))==VA_END_SIGNATURE)
            break;

         err=-1;
         ERROR_MSG_FMT(VARG_ERROR_MSG_NULL_PARM, argc-1)

         if (v)
            goto while_vargs_continue;

         if ((MAX_ARG_OVF-2)>argc)
            ERROR_MSG_FMT(VARG_ERROR_MSG_NULL_PARM, argc)

      }

while_vargs_continue:
      if ((MAX_ARG_OVF-2)>=argc)
         if (!check_msgsig((C_TEST_VARGS_MSG *)v)) {
            err=-4;
            ERROR_MSG_FMT("ERROR: Invalid message at argument %d", argc)
         }
   }
   va_end(args);

   if (argc>2)
      argc-=2;
   else if (argc==2) {
      if (!err)
         return (C_TEST_VARGS_MSG_HEADER *)VA_END_SIGNATURE;

      ERROR_MSG_FMT("ERROR %d: Invalid empty args", err);
      return NULL;
   } else {
      ERROR_MSG("ERROR: vargs_setter must be initialized only with CTEST_SETTER macro.");
      return NULL;
   }

   va_copy(args, args_cpy);
   va_start(args, initial);
   if (err) {
      ret=NULL;

vargs_setter_RET:
      ERROR_MSG_FMT("Error(s) occurred with last error %d. Closing arguments before quit ...", err);

      for (initial=0;initial<argc;initial++) {
         INFO_MSG_FMT("Closing argument %d ...", initial)
         if ((err=close_varg((C_TEST_VARGS_MSG *)(v=(void *)va_arg(args, void *))))) {
            if (err==CLOSE_VARG_ERR_WRONG_SIG)
               if (!c_test_is_header_invalid((C_TEST_VARGS_MSG_HEADER *)v)) {
                  ERROR_MSG("Error: Found forbidden arguments inside argument setter. Trying to close");

                  if ((err=free_vargs((C_TEST_VARGS_MSG_HEADER *)v))) ERROR_MSG_FMT("Error %d: Closing failed", err)
                  else INFO_MSG("Closed success!");
               }

         } else
            SUCCESS_MSG_FMT("Argument %d closed", initial)

      }

      if (ret) {
         SUCCESS_MSG_FMT("Finally close vargs handler at address (%p)", ret)
         free(ret);// All children was cleared using close_varg. Here we will NOT use free_vargs() in this case
      }

      ERROR_MSG("Closed all arguments");
      va_end(args);
      return NULL;
   }

   if (!(ret=c_test_vargs_create())) {
      ERROR_MSG("Fatal: Can't create vargs setter ...")
      goto vargs_setter_EXIT1;
   }

   vargs_msgs=ret->vargs_msgs;

   for (initial=0;initial<argc;initial++) {
      if (check_vargs_sigmsg_exists(ret->vargs_msgs, ((C_TEST_VARGS_MSG *)(v=(void *)va_arg(args, void *)))->sig)) {
         err=-127;
         ERROR_MSG("ERROR: Repeated arguments. Closing ...")
         goto vargs_setter_EXIT1;
      }

      *(vargs_msgs++)=(C_TEST_VARGS_MSG *)v;

   }

   va_end(args);
   return (void *)ret;

vargs_setter_EXIT1:
   va_end(args);
   va_copy(args, args_cpy);
   va_start(args, initial);

   goto vargs_setter_RET;

#undef MAX_ARG_OVF
}

#define LOAD_TEST_VARGS_ERROR_TOO_MANY_ARGS 10
#define LOAD_TEST_VARGS_ERROR_MISSING_ARGUMENTS 11
#define LOAD_TEST_VARGS_ERROR_LOAD_WRONG_ARGUMENT_1 12
#define LOAD_TEST_VARGS_ERROR_LOAD_WRONG_ARGUMENT_2 13
#define LOAD_TEST_VARGS_ERROR_IS_NULL 14
#define LOAD_TEST_VARGS_ERROR_HEADER_INVALID 15
#define LOAD_TEST_VARGS_END_SIGNATURE -15
static int load_test_vargs(void **vargs, ...)
{
   int i;
   void *ptr[3];
   va_list ap;

#define MAX_ARG 3+1
   *vargs=NULL;
   va_start(ap, vargs);
   for (i=0;i<MAX_ARG;) {
      if (i==(MAX_ARG-1)) {
         va_end(ap);
         return LOAD_TEST_VARGS_ERROR_TOO_MANY_ARGS;
      }
      if ((ptr[i++]=(void *)va_arg(ap, void *))==VAS_END_SIGNATURE)
         break;
   }
   va_end(ap);
#undef MAX_ARG

   if (i==1)
      return LOAD_TEST_VARGS_ERROR_MISSING_ARGUMENTS;

   (i==2)?(i=0):(i=1);

   if (ptr[i++])
      return LOAD_TEST_VARGS_ERROR_LOAD_WRONG_ARGUMENT_1;

   if (ptr[i]!=VAS_END_SIGNATURE)
      return LOAD_TEST_VARGS_ERROR_LOAD_WRONG_ARGUMENT_2;

   if (ptr[1]==VAS_END_SIGNATURE)
      return LOAD_TEST_VARGS_END_SIGNATURE;

   if (!ptr[0])
      return LOAD_TEST_VARGS_ERROR_IS_NULL;

   if (c_test_is_header_invalid(ptr[0]))
      return LOAD_TEST_VARGS_ERROR_HEADER_INVALID;

   *vargs=(C_TEST_VARGS_MSG_HEADER *)ptr[0];
   return 0;
}

static char *parse_vas_msg(int *msg_sz, void *vas, uint32_t sig)
{
   C_TEST_VARGS_MSG *res;
   char *p;

   *msg_sz=0;

   if (!vas)
      return NULL;

   p=NULL;
   if ((res=check_vargs_sigmsg_exists(((C_TEST_VARGS_MSG_HEADER *)vas)->vargs_msgs, sig)))
      if (res->msg_sz>0) {
         p=res->msg;
         *msg_sz=res->msg_sz;
      }

   return p;
}

//
#define PRINT_CALLBACK \
   if (((C_TEST_HEADER *)_c_test_ptr)->on_test_fn)\
      ((C_TEST_HEADER *)_c_test_ptr)->on_test_fn(ctx);

#define SHOW_USER_NOTIFICATION \
   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_TITLE)))\
      TITLE_MSG_FMT("%.*s", p_sz, p)\
\
   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_INFO)))\
      INFO_MSG_FMT("%.*s", p_sz, p)\
\
   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_WARNING)))\
      WARN_MSG_FMT("%.*s", p_sz, p)

static void print_assert_int(void *ctx, void *vas)
{
   int error, idx, p_sz;
   uint32_t desc_type;
   char *p;
   C_TEST_TYPE_INT *type=(C_TEST_TYPE_INT *)ctx;

   const char *print_assert_int_msg[][2] = {
      {"\"%s\". FALSE (%d) -> ok", "\"%s\". Expected FALSE (%d), but found TRUE (%d) -> fail"},
      {"\"%s\". TRUE (%d) -> ok", "\"%s\". Expected TRUE (%d), but found FALSE (%d) -> fail"},
      {"\"%s\". Expected %d (0x%08x) == result %d (0x%08x) -> ok", "\"%s\". Expected %d (0x%08x), but found %d (0x%08x) -> fail"},
      {"\"%s\". Unexpected %d (0x%08x) != result %d (0x%08x) -> ok", "\"%s\". Unexpected %d (%08x) == result %d (0x%08x) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if ((desc_type=type->header.desc.type)==TYPE_ASSERT_TRUE)
      idx=1;
   else if (desc_type==TYPE_ASSERT_EQUAL_INT)
      idx=2;
   else if (desc_type==TYPE_ASSERT_NOT_EQUAL_INT) {
      error=!error;
      idx=3;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      //ERROR_MSG(type->header.on_error)

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      if (idx>1)
         ERROR_MSG_FMT(print_assert_int_msg[idx][1],
            type->header.desc.fn_name,
            type->expected, type->expected,
            type->result, type->result
        )
      else
         ERROR_MSG_FMT(print_assert_int_msg[idx][1],
            type->header.desc.fn_name,
            type->expected,
            type->result
        )

      abort_tests();
   }

   //SUCCESS_MSG(type->header.on_success)

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   if (idx>1)
      SUCCESS_MSG_FMT(print_assert_int_msg[idx][0],
         type->header.desc.fn_name,
         type->expected, type->expected,
         type->result, type->result
     )
   else
      SUCCESS_MSG_FMT(print_assert_int_msg[idx][0],
         type->header.desc.fn_name,
         type->expected,
         type->result
     )

}

static void print_assert_longint(void *ctx, void *vas)
{
   C_TEST_TYPE_LONG_INT *type=(C_TEST_TYPE_LONG_INT *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_long_int_msg[][2] = {
      {"\"%s\". Expected %d (0x%016llx) == result %d (0x%016llx) -> ok", "\"%s\". Expected %d (0x%016llx), but found %d (0x%016llx) -> fail"},
      {"\"%s\". Unexpected %d (0x%016llx) != result %d (0x%016llx) -> ok", "\"%s\". Unexpected %d (%016llx) == result %d (0x%016llx) -> fail"}
   };

   PRINT_CALLBACK

   error=(type->expected!=type->result);

   idx=0;
   if (type->header.desc.type==TYPE_TYPE_ASSERT_NOT_EQUAL_LONG_INT) {
      error=!error;
      idx=1;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_long_int_msg[idx][1],
         type->header.desc.fn_name,
         type->expected, type->expected,
         type->result, type->result
      )

      abort_tests();
   }

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_long_int_msg[idx][0],
      type->header.desc.fn_name,
      type->expected, type->expected,
      type->result, type->result
   )
}

static void print_assert_double(void *ctx, void *vas)
{
   C_TEST_TYPE_DOUBLE *type=(C_TEST_TYPE_DOUBLE *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_long_int_msg[][2] = {
      {"\"%s\". Expected %.17g == result %.17g with delta = %e -> ok", "\"%s\". Expected %.17g, but found %.17g with delta = %e -> fail"},
      {"\"%s\". Unexpected %.17g != result %.17g with delta = %e -> ok", "\"%s\". Unexpected %.17g == result %.17g with delta = %e -> fail"}
   };

   PRINT_CALLBACK

   error=(fabs(type->expected-type->result)>fabs(type->delta));

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_DOUBLE) {
      idx=1;
      error=!error;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_long_int_msg[idx][1],
         type->header.desc.fn_name,
         type->expected, type->result, type->delta
      )

      abort_tests();
   }

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_long_int_msg[idx][0],
      type->header.desc.fn_name,
      type->expected, type->result, type->delta
   )

}

static void print_assert_byte(void *ctx, void *vas)
{
   C_TEST_TYPE_BYTE *type=(C_TEST_TYPE_BYTE *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_byte_msg[][2] = {
      {
          "\"%s\". (%llu) bytes at pointer expected (%p) == pointer result (%p) -> ok",
          "\"%s\". (%llu) bytes at pointer expected (%p) != pointer result (%p) -> fail"
      },
      {
          "\"%s\". (%llu) bytes at pointer unexpected (%p) != pointer result (%p) -> ok", 
          "\"%s\". (%llu) bytes at pointer unexpected (%p) == pointer result (%p) -> fail"
      }
   };

   PRINT_CALLBACK

   error=memcmp(type->expected, type->result, type->size);

   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_BYTE) {
      idx=1;
      error=!error;
   }

   SHOW_USER_NOTIFICATION

   if (error) {

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_byte_msg[idx][1],
         type->header.desc.fn_name,
         type->size,
         type->expected, type->result
      )

      abort_tests();
   }

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_byte_msg[idx][0],
      type->header.desc.fn_name,
      type->size,
      type->expected, type->result
   )
}

static void print_assert_string(void *ctx, void *vas)
{
   C_TEST_TYPE_STRING *type=(C_TEST_TYPE_STRING *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_string_msg[][2] = {
      {
          "\"%s\". Expected \"%s\" at pointer (%p) == result \"%s\" at pointer (%p) -> ok",
          "\"%s\". Expected \"%s\" at pointer (%p) != result \"%s\" at pointer (%p) -> fail"
      },
      {
          "\"%s\". Unexpected \"%s\" at pointer (%p) != result \"%s\" at pointer (%p) -> ok", 
          "\"%s\". Unexpected \"%s\" at pointer (%p) == result \"%s\" at pointer (%p) -> fail"
      }
   };

   PRINT_CALLBACK

   error=((type->header.desc.type==TYPE_ASSERT_EQUAL_STRING_IGNORE_CASE)||(type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE))?
         (strcasecmp(type->expected, type->result)):(strcmp(type->expected, type->result));

   idx=0;
   if ((type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_STRING)||(type->header.desc.type==TYPE_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE)) {
      idx=1;
      error=!error;
   }

   SHOW_USER_NOTIFICATION

   if (error) {
      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_string_msg[idx][1],
         type->header.desc.fn_name,
         type->expected, type->expected,
         type->result, type->result
      )

      abort_tests();
   }

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_string_msg[idx][0],
      type->header.desc.fn_name,
      type->expected, type->expected,
      type->result, type->result
   )
}

static void print_assert_nullable(void *ctx, void *vas)
{
   C_TEST_TYPE_NULLABLE *type=(C_TEST_TYPE_NULLABLE *)ctx;
   int error, idx, p_sz;
   char *p;

   const char *print_assert_byte_msg[][2] = {
      {
          "\"%s\". Expected not NULL. Result (%p) -> ok",
          "\"%s\". Expected not NULL pointer but pointer (%s) found -> fail"
      },
      {
          "\"%s\". Expected NULL == result (%s) -> ok",
          "\"%s\". Expected NULL pointer but pointer (%p) found -> fail"
      }
   };

   PRINT_CALLBACK

   error=(type->pointer==NULL);
   idx=0;
   if (type->header.desc.type==TYPE_ASSERT_NULL) {
      idx=1;
      error=!error;
   }

   SHOW_USER_NOTIFICATION

   if (error) {

      if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_ERROR)))
         ERROR_MSG_FMT("%.*s", p_sz, p)

      free_vargs(vas);

      ERROR_MSG_FMT(print_assert_byte_msg[idx][1], type->header.desc.fn_name, (type->pointer)?(type->pointer):"NULL")

      abort_tests();
   }

   if ((p=parse_vas_msg(&p_sz, vas, C_TEST_VARGS_SUCCESS)))
      SUCCESS_MSG_FMT("%.*s", p_sz, p)

   free_vargs(vas);

   SUCCESS_MSG_FMT(print_assert_byte_msg[idx][0], type->header.desc.fn_name, (type->pointer)?(type->pointer):"NULL")
}

static void add_test(void *ctx, void *vas)
{
   int err;
   void *p;
   size_t sz_tmp;

   if (_c_test_ptr) {

      sz_tmp=(((C_TEST_HEADER *)_c_test_ptr)->tests)*sizeof(C_TEST_FN)+sizeof(C_TEST_HEADER);

      if (!(p=realloc(_c_test_ptr, sz_tmp+sizeof(C_TEST_FN)))) {
         printf("\nFatal: Error when realloc test pointer @ %p\n", _c_test_ptr);
         free(_c_test_ptr);
         if ((err=free_vargs(vas)))
            ERROR_MSG_FMT("free_vargs @ add_test on memory reallocation error = %d at pointer (%p)", err, vas) 
         exit(1);
      }

      goto add_test_EXIT1;
   }

   if (!(p=malloc((sz_tmp=sizeof(C_TEST_HEADER))+sizeof(C_TEST_FN)))) {
      printf("\nFatal: Error when initialize pointer @ NULL");
      if ((err=free_vargs(vas)))
         ERROR_MSG_FMT("free_vargs @ add_test on memory allocation for creating header error = %d at pointer (%p)", err, vas) 
      exit(1);
   }

   TITLE_MSG("Begin adding test ...")

   C_TEST_INITIAL_ADD
   C_TEST_INITIAL_ADD_FN_ALL_NULL

add_test_EXIT1:
   memcpy((_c_test_ptr=p)+sz_tmp, ctx, ((C_TEST_TYPE_HEADER *)ctx)->desc.blk_size);
   TITLE_MSG_FMT("Adding test instance \"%s\" (%d)", ((C_TEST_FN_DESCRIPTION *)ctx)->fn_name, ++((C_TEST_HEADER *)p)->tests)

   if (((C_TEST_HEADER *)p)->on_add_test_fn)
      ((C_TEST_HEADER *)p)->on_add_test_fn(ctx);
}

#define ASSERT_PRELOAD \
   type.header.on_error=on_error_msg;\
   type.header.on_success=on_success;\
   type.expected=expected;\
   type.result=result;

//TODO Temporary for adjustment
#define ASSERT_PRELOAD_TEMP \
   type.expected=expected;\
   type.result=result;

#define TEST_BEGIN \
   add_test((void *)&type, vas); \
   begin_test(vas);


static void assert_equal_bool(
   int expected,
   int result,
   void *vas
)
{
   static C_TEST_TYPE_BOOL type;

   (expected==C_TEST_TRUE)?(type.header.desc=C_TEST_FN_DESCRIPTION_ASSERT_TRUE):(type.header.desc=C_TEST_FN_DESCRIPTION_ASSERT_FALSE);
   ASSERT_PRELOAD_TEMP // TODO Replace TO ASSERT_PRELOAD
   TEST_BEGIN
}

#define CHECK_BOOL(fn_name) \
   if ((value!=C_TEST_FALSE)&&(value!=C_TEST_TRUE)) {\
      ERROR_MSG_FMT("Wrong value %d in %s. Was expected C_TEST_FALSE or C_TEST_TRUE but found %d (0x%08x)", value, fn_name, value, value)\
      abort_tests();\
   }

// BEGIN WARN: To be only used in asserts function only
//in arguments
//out: vas
#define VERIFY_VAS_SIG_VALID (uint64_t)0x0000000167abdd72
#define INVALID_ARGS_PARMS_MSG "\"%s\". Error %d: Invalid arguments parameters"
int assert_warning_util(void **vas, void *p, const char *FN_MACRO_NAME)
{
   int err;
   uint64_t sig;

   *vas=NULL;
   if (!p) {
      ERROR_MSG_FMT("Error. Null parameter. Try %s", FN_MACRO_NAME)
      return -100;
   }

   if (p==VAS_END_SIGNATURE) {
      if (((sig=*((uint64_t *)p))!=VERIFY_VAS_SIG_VALID)) {
         ERROR_MSG_FMT("Wrong message in %s signature @ (%p) with value (0x%016x)", FN_MACRO_NAME, p, (unsigned long long int)sig)
         return -101;
      }
      return 0;
   }

   if ((err=load_test_vargs(vas, p, NULL, VAS_END_SIGNATURE)))
      ERROR_MSG_FMT(INVALID_ARGS_PARMS_MSG, FN_MACRO_NAME, err)

   return err;

}
// END WARN

void assert_false(int value, ...)
{
   void *vas;
   va_list va;

   CHECK_BOOL("assert_false")
   va_start(va, value);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_FALSE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_equal_bool(C_TEST_FALSE, value, vas);
}

void assert_true(int value, ...)
{
   void *vas;
   va_list va;

   CHECK_BOOL("assert_true")
   va_start(va, value);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_TRUE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_equal_bool(C_TEST_TRUE, value, vas);
}

//static void assert_int(int expected, int result, C_TEST_FN_DESCRIPTION *desc, const char *on_error_msg, const char *on_success)
static void assert_int(int expected, int result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_INT type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD_TEMP
//   ASSERT_PRELOAD
   TEST_BEGIN
}

void assert_equal_int(int expected, int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_int(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_INT, vas);
}

void assert_not_equal_int(int expected, int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_int(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_INT, vas);
}

static void assert_longint(long long int expected, long long int result, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_LONG_INT type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   //ASSERT_PRELOAD
   ASSERT_PRELOAD_TEMP
   TEST_BEGIN
}

void assert_equal_longint(long long int expected, long long int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_LONG_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_longint(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_LONG_INT, vas);
}

void assert_not_equal_longint(long long int expected, long long int result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_LONG_INT")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_longint(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_LONG_INT, vas);
}

static void assert_double(double expected, double result, double delta, C_TEST_FN_DESCRIPTION *desc, void *vas)
{
   static C_TEST_TYPE_DOUBLE type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD_TEMP
   type.delta=delta;
   TEST_BEGIN
}

void assert_equal_double(double expected, double result, double delta, ...)
{
   void *vas;
   va_list va;

   va_start(va, delta);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_DOUBLE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_double(expected, result, delta, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_DOUBLE, vas);
}

void assert_not_equal_double(double expected, double result, double delta, ...)
{
   void *vas;
   va_list va;

   va_start(va, delta);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_DOUBLE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_double(expected, result, delta, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_DOUBLE, vas);
}

static void assert_byte(
   void *expected,
   void *result,
   size_t size,
   C_TEST_FN_DESCRIPTION *desc,
   void *vas
)
{
   static C_TEST_TYPE_BYTE type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD_TEMP
   type.size=size;
   type.free_on_error_cb=NULL; //TODO Remove
   type.free_on_error_ctx=NULL; // TODO remove
   TEST_BEGIN
}

void assert_equal_byte(
   void *expected,
   void *result,
   size_t size,
   ...
)
{
   void *vas;
   va_list va;

   va_start(va, size);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_BYTE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_byte(expected, result, size, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_BYTE, vas);
}

void assert_not_equal_byte(
   void *expected,
   void *result,
   size_t size,
   ...
)
{
   void *vas;
   va_list va;

   va_start(va, size);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_BYTE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_byte(expected, result, size, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_BYTE, vas);
}

static void assert_string(
   const char *expected,
   const char *result,
   C_TEST_FN_DESCRIPTION *desc,
   void *vas
)
{
   static C_TEST_TYPE_STRING type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
   ASSERT_PRELOAD_TEMP
   TEST_BEGIN

}

void assert_equal_string(const char *expected, const char *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_STRING")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_string(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_STRING, vas);
}

void assert_not_equal_string(const char *expected, const char *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_STRING")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_string(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_STRING, vas);
}

void assert_equal_string_ignore_case(const char *expected, const char *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_EQUAL_STRING_IGNORE_CASE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_string(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_EQ_STRING_IGNORE_CASE, vas);
}

void assert_not_equal_string_ignore_case(const char *expected, const char *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_EQUAL_STRING_IGNORE_CASE")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_string(expected, result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_EQ_STRING_IGNORE_CASE, vas);
}

static void assert_nullable(
   void *result,
   C_TEST_FN_DESCRIPTION *desc,
   void *vas
)
{
   static C_TEST_TYPE_NULLABLE type;

   memcpy(&type.header.desc, desc, sizeof(type.header.desc));
//   type.should_be_null=(desc==&C_TEST_FN_DESCRIPTION_ASSERT_NULL);
   type.header.on_error=NULL;//on_error_msg; TODO Remove
   type.header.on_success=NULL;//on_success; TODO remove
   type.pointer=result;
   type.free_on_error_cb=NULL;//free_on_error_cb; TODO remove
   type.free_on_error_ctx=NULL;//free_on_error_ctx; TODO remove
   TEST_BEGIN
}

void assert_null(void *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NULL")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);
   assert_nullable(result, &C_TEST_FN_DESCRIPTION_ASSERT_NULL, vas);
}

void assert_not_null(void *result, ...)
{
   void *vas;
   va_list va;

   va_start(va, result);
   if (assert_warning_util(&vas, (void *)va_arg(va, void *), "C_ASSERT_NOT_NULL")) {
      va_end(va);
      abort_tests();
   }
   va_end(va);

   assert_nullable(result, &C_TEST_FN_DESCRIPTION_ASSERT_NOT_NULL, vas);
}

uint64_t *get_va_end_signature()
{
   static uint64_t va_end_signature_u64=0x00000000df3f6198;
   return &va_end_signature_u64;
}

uint64_t *get_vas_end_signature()
{
   static uint64_t vas_end_signature_u64=0x0000000167abdd72;
   return &vas_end_signature_u64;
}

#ifdef DEBUG_TEST
 inline int load_test_vargs_for_test(void **vargs, ...)
 {
    void *ctx;
    va_list va;
    va_start(va, vargs);
    ctx=(void *)va_arg(va, void *);
    va_end(va);

    return load_test_vargs(vargs, ctx, NULL, VAS_END_SIGNATURE);
 }

 inline int free_vargs_for_test(void *vargs)
 {
    return free_vargs(vargs);
 }

 static char *ctest_setter_has_util(void *ctest_setter, uint32_t sig)
 {
    C_TEST_VARGS_MSG *res;

    if (!ctest_setter)
       return NULL;

    if ((res=check_vargs_sigmsg_exists(((C_TEST_VARGS_MSG_HEADER *)ctest_setter)->vargs_msgs, sig)))
      return res->msg;

    return NULL;
 }

 inline char *ctest_setter_has_title(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_TITLE);
 }

 inline char *ctest_setter_has_info(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_INFO);
 }

 inline char *ctest_setter_has_warn(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_WARNING);
 }

 inline char *ctest_setter_has_onerror(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_ERROR);
 }

 inline char *ctest_setter_has_onsuccess(void *ctest_setter)
 {
    return ctest_setter_has_util(ctest_setter, C_TEST_VARGS_SUCCESS);
 }

 void show_message_text()
 {
    const char *msg="This is a simple %s message";

     TITLE_MSG_FMT(msg, "TITLE")
     ERROR_MSG_FMT(msg, "ERROR")
     SUCCESS_MSG_FMT(msg, "SUCCESS")
     WARN_MSG_FMT(msg, "WARNING")
     INFO_MSG_FMT(msg, "INFO")
 }

#endif

