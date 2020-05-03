/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "f_nano_crypto_util.h"

#define USAGE \
"USAGE\n\
======\
\n\n\tVerifies if signature is valid given a NANO/XRB wallet or raw hex public key\n\n\
\t/example10 <HASH_BLOCK> <SIGNATURE> <PUBLIC_KEY|NANO_WALLET|XRB_WALLET>\n\n\n"

int main(int argc, char **argv)
{

   int err;
   uint32_t type;

   if (argc==1) {

      printf(LICENSE);
      printf(USAGE);

      return 0;

   }

   if (argc>4) {

      printf("\n\nToo many arguments\n\n");

      return 0;

   }

   if (argc<4) {

      printf("\n\nToo few arguments\n\n");

      return 0;

   }

   ((is_nano_prefix((const char *)argv[3], NANO_PREFIX))||(is_nano_prefix((const char *)argv[3], XRB_PREFIX)))?
      (type=F_VERIFY_SIG_NANO_WALLET):(type=F_VERIFY_SIG_ASCII_HEX);

   if ((err=(f_verify_signed_data(
      (const unsigned char *)argv[2],
      (const unsigned char *)argv[1],
      strlen(argv[1]),
      (const void *)argv[3],
      type|F_IS_SIGNATURE_RAW_HEX_STRING|F_MESSAGE_IS_HASH_STRING)))>0) {

      err=0;
      printf("\nVALID SIGNATURE ;)\n");

   } else if (err) {

      printf("\nFUNCTION ERROR %d\n", err);

      return err;

   } else
      printf("\nINVALID SIGNATURE :(\n\n");

   printf("\nFinally HELLO WORLD\n");

   return err;

}

