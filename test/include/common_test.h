#include <stdio.h>
#include <string.h>
#include <f_nano_crypto_util.h>
#include <ctest/asserts.h>
#include <cJSON.h>
#define BUF_MSG_SZ 4096
char *msgbuf();
void clear_msgbuf();
void gen_rand_no_entropy(void *, size_t);

