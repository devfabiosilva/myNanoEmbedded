/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// seg 06 abr 2020 01:19:16 -03 

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "f_nano_crypto_util.h"

int main(int argc, char **argv)
{

   int err, type;
   uint64_t n;
   char *ptr=NULL, *number=NULL, *prefix=NULL, *p;
   char buf[256];
   NANO_SEED SEED;
   NANO_PRIVATE_KEY_EXTENDED PRIVATE_KEY;
   NANO_PUBLIC_KEY_EXTENDED PUBLIC_KEY;

   if (argc==1) {

      printf(LICENSE);

      printf("\nUSAGE:\n\n\texample7 [file|seed|bip39] <FILENAME|SEED|BIP39> n <WALLET_NUMBER> p (OPTIONAL) <nano|xrb>\n\n\n");

      return 0;

   }

   if (argc>7) {

      printf("\nError: Too many arguments\n\n");

      return -1;

   }

   type=0;

   for (err=1;err<argc;) {

      if (strcmp("file", p=argv[err++])==0) {

         if (ptr) {

            printf("\nStrange argument in file option\n\n");

            return -4;

         }

         if (argc==err) {

            printf("\nError: Missing file\n\n");

            return -2;

         }

         ptr=argv[err++];

      } else if (strcmp("seed", p)==0) {

         if (ptr) {

            printf("\nStrange argument in seed parameter\n\n");

            return -5;

         }

         if (argc==err) {

            printf("\nError. Missing seed\n\n");

            return -6;

         }

         type=1;

         ptr=argv[err++];

      } else if (strcmp("bip39", p)==0) {

         if (ptr) {

            printf("\nStrange argument in Bip39 parameter\n\n");

            return -5;

         }

         if (argc==err) {

            printf("\nError. Missing Bip39 word list\n\n");

            return -6;

         }

         type=2;

         ptr=argv[err++];

      } else if (strcmp("n", p)==0) {

         if (argc==err) {

            printf("\nMissing wallet number\n\n");

            return -7;

         }

         if (number) {

            printf("\nMaybe repeated number wallet number'%s'\n\n", number);

            return -8;

         }

         number=argv[err++];

      } else if (strcmp("p", p)==0) {

         if (argc==err) {

            printf("\nMissing prefix.\n\n");

            return -9;

         }

         if (prefix) {

            printf("\nMaybe repeated prefix '%s'\n\n", prefix);

            return -10;

         }

         prefix=argv[err++];

      } else {

         printf("\n\nERROR: Invalid option\n\n");

         return -3;

      }

   }

   if (!ptr) {

      printf("\nMissing [file|seed|bip39] argument\n\n");

      return -11;

   }

   if (!number) {

      printf("\nMissing wallet number parameter\n\n");

      return -12;

   }

   if (err=f_convert_to_long_int((unsigned long int *)&n, number, 11)) {

      printf("\nParsed nano wallet number is not an number or number is too large.\n\n");

      return -13;

   }

   if (n>(uint64_t)((uint32_t)-1)) {

      printf("\n\nNano wallet value is greater than (2**32 - 1)\n\n");

      return -14;

   }

   if (prefix) {

      if (strcmp("nano", prefix)==0)
         prefix=NANO_PREFIX;
      else if (strcmp("xrb", prefix)==0)
         prefix=XRB_PREFIX;
      else {

         printf("\n\nUnknown prefix '%s'\n\nChoose \"nano\" or \"xrb\"\n\n", prefix);

         return -15;

      }

   } else
      prefix=NANO_PREFIX;


   if (type==1) {

      if (strlen(ptr)!=64) {

         printf("\nInvalid SEED size. It must be 32 bytes long\n\n");

         return -16;

      }

      if ((err=f_str_to_hex(SEED, ptr))) {

         printf("\nError when converting \"%s\" to raw hex stream %d\n\n", p, err);

         goto EXIT;

      }

   } else if (type) {

      if ((err=f_bip39_to_nano_seed(SEED, ptr, BIP39_DICTIONARY_SAMPLE))) {

         printf("\nError. Can't parse Bip39 word list \"%s\" to Nano SEED %d\n\n", ptr, err);

         goto EXIT;

      }

   } else {

      printf("\nOpening \"%s\" ...\nType your PASSWORD:", ptr);

      if ((err=get_console_passwd(buf, sizeof(buf)-1))) {

         printf("Error in \"get_console_passwd\" %d. Exiting\n", err);

         goto EXIT;

      }

      if ((err=f_read_seed(SEED, buf, ptr, 0, READ_SEED_FROM_FILE))) {

         printf("Error in \"f_read_seed\" %d. Can't read Nano SEED from file. Exiting\n", err);

         goto EXIT;

      }

   }

   if (err=f_seed_to_nano_wallet(PRIVATE_KEY, PUBLIC_KEY, SEED, (uint32_t)n)) {

      printf("\nError when extracting \"f_seed_to_nano_wallet\" %d\n", err);

      goto EXIT;

   }

   printf("\nWALLET NUMBER %d\n", (uint32_t)n);
   printf("-----------------------------------------------------------\n");

   printf("\nPRIVATE KEY = \"%s\" (DON'T TELL IT TO ANYBODY)\n", f_nano_key_to_str(buf, PRIVATE_KEY));
   printf("\nPUBLIC KEY = \"%s\"\n", f_nano_key_to_str(buf, PUBLIC_KEY));

   if (err=pk_to_wallet(buf, prefix, PUBLIC_KEY)) {

      printf("\nError when parsing PUBLIC KEY to Base32 encoded string in \"pk_to_wallet\" %d\n", err);

      goto EXIT;

   }

   printf("NANO Wallet %s\n", buf);
   printf("============================================================\n");

   printf("\n\nFinally HELLO WORLD !!!\n\n");

   err=0;

EXIT:
   memset(SEED, 0, sizeof(SEED));
   memset(PRIVATE_KEY, 0, sizeof(PRIVATE_KEY));
   memset(PUBLIC_KEY, 0, sizeof(PUBLIC_KEY));
   memset(buf, 0, sizeof(buf));

   return err;

}

