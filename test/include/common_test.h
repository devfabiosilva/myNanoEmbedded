#include <stdio.h>
#include <string.h>
#include <f_nano_crypto_util.h>
#include <ctest/asserts.h>
#include "mbedtls/base64.h"
#include <cJSON.h>
#define BUF_MSG_SZ 5120
char *msgbuf();
char *clear_msgbuf();
void gen_rand_no_entropy(void *, size_t);
#define OR_ELSE_NULL_STR(s) (s)?s:"NULL"
