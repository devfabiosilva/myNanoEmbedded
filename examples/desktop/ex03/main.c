/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdio.h>
#include <string.h>
#include "f_nano_crypto_util.h"

#define OK " [ OK ]\n"
#define FAIL " [ FAIL ]\n"
#define SUCCESS " [SUCCESS]\n\n"

#define HELP "\
USAGE:\n\
======\
\n\n\
\t\"help\" -> This help\n\
\t\"open\" -> Open a filename containing a Nano SEED encrypted with password and shows SEED and Bip39 encoded word list.\n\n\
\t\tEXAMPLE: ./example3 open nanoseed.nse\n\n\n\
\t\"gen\"  -> Genarates a Nano SEED and encrypts using non deterministic cryptography function and saves it to a file protected by password.\n\n\
\t\tEXAMPLE: ./example3 gen nanoseed.nse 1\n\n\
\t\tWHERE:\n\n\
\t\t\t1- For PARANOIC entropy (high recommended but very slow)\n\
\t\t\t2- For EXELENT entropy (recommended but slow)\n\
\t\t\t3- For GOOD entropy (normal)\n\
\t\t\t4- For NOT ENOUGH entropy (medium but fast)\n\
\t\t\t5- For NOT RECOMMENDED entropy (not recommended but very fast)\n\n\n"

void gen_rand_no_entropy(void *output, size_t output_len)
{
   FILE *f;
   size_t rnd_sz, left;

   if (!(f=fopen("/dev/urandom", "r")))
      return;

   rnd_sz=0;
   left=output_len;

   while ((rnd_sz+=fread(output+rnd_sz, 1, left, f))<output_len)
      left-=rnd_sz;

   fclose(f);

   return;

}

int main(int argc, char **argv)
{

   int i;
   uint32_t n;
   char buf[512];
   NANO_SEED SEED;
   char *filename;

   if (argc==1) {

      printf(LICENSE);
      printf("\nChoose example3 [command] <param1> <param2>\n==========================================\n\n");
      printf("\nexample3 open <filename.nse>            => Open a encrypted file containing SEED\n");
      printf("\nexample3 gen <filename.nse> <Number>    => Generates a SEED given a password where <Number> = 1 (strongest entropy) to 5 (Not recommended)\n\n");

      return 0;

   }

   if (strcmp("open", argv[i=1])==0) {

      if (argc>3) {

         printf("\nToo many arguments to open an encrypted Nano SEED file\n");

         return -1;

      }

      if ((++i)==argc) {

         printf("\nMissing argument. Required a filename\n");

         return 1;

      }

      filename=argv[i];

   } else if (strcmp("gen", argv[i])==0) {

      if (argc>4) {

         printf("\nToo many arguments to generate Nano SEED\n");

         return 7;

      }

      if ((++i)==argc) {

         printf("\nMissing argument. Required a filename\n");

         return 2;

      }

      filename=argv[i];

      if ((++i)==argc) {

         printf("\nMissing argument. Required a entropy number\n");

         return 3;

      }

      if (f_is_integer(argv[i], 2)) {

         if ((n=f_sel_to_entropy_level((int)*argv[i]))==0) {

            printf("\nInvalid entropy number\n");

            return 9;

         }

         i=0;

      } else {

         printf("\nERROR: Invalid number. Allowed only positive number between 1-5\n");

         return 8;

      }

   } else if (strcmp("help", argv[i])==0) {

      printf(HELP);

      return 0;

   } else {

      printf("\nUnknown option. Choose command \"help\" for help or \"open\" to open an encrypted file or \"gen\" command to generate an encrypted file SEED with Password\n");

      return 5;

   }

   if (i) {

      printf("\nOpening \"%s\" ...\nType your PASSWORD:", filename);

      if ((i=get_console_passwd(buf, sizeof(buf)-1))) {

         printf(FAIL);
         printf("Error in \"get_console_passwd\" %d. Exiting\n", i);

         return i;

      }

      if ((i=f_read_seed(SEED, buf, filename, 0, READ_SEED_FROM_FILE))) {

         printf(FAIL);
         printf("Error in \"f_read_seed\" %d. Can't read Nano SEED from file. Exiting\n", i);

         return i;

      }

      printf(OK);
      printf("SEED: \"%s\" (DON'T TELL IT TO ANYBODY).\n", f_nano_key_to_str(buf, SEED));

      printf("Converting your SEED in Bip39 (DON'T TELL IT TO ANYBODY)");

      if (i=f_nano_seed_to_bip39(buf, sizeof(buf), NULL, SEED, BIP39_DICTIONARY_SAMPLE)) {

         printf(FAIL);
         printf("\nError when parse SEED to Bip39 in \"f_nano_seed_to_bip39\" %d\n", i);

         return i;

      }

      printf(OK);
      printf("Your Bip39: \"%s\".", buf);
      printf(SUCCESS);

      return 0;

   }

   f_random_attach(gen_rand_no_entropy);

   printf("\nPreparing to generate a new Nano SEED with entropy %s and store in a file named \"%s\" ...\nType your PASSWORD:", f_get_entropy_name(n), filename);

   if ((i=get_console_passwd(buf, sizeof(buf)/2-1))) {

      if (i==13)
         printf("\nMandatory: PASSWORD");

      printf(FAIL);
      printf("Error in \"get_console_passwd\" %d. Exiting\n", i);

      return i;

   }

   printf(OK);
   printf("Verifying your password strength ...");

   if ((i=f_pass_must_have_at_least(buf, 48, 8, 32, 
      (F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER|F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE|
       F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL|F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE)))&F_PASS_IS_TOO_SHORT) {

      printf("\nError. Password is too short. It must have at least 8 characters"FAIL);

      return 40;

   }

   if (i&F_PASS_IS_TOO_LONG) {

      printf("\nError. Password is too long"FAIL);

      return 41;

   }

   if (i&F_PASS_IS_OUT_OVF) {

      printf("\nError. Password length overflow buffer"FAIL);

      return 42;

   }
      
   if (i&F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER)
      printf("\nError. Password must have at least one number"FAIL);

   if (i&F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE)
      printf("\nError. Password must have at least one upper case"FAIL);

   if (i&F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE)
      printf("\nError. Password must have at least one lower case"FAIL);

   if (i&F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL)
      printf("\nError. Password must have at least one symbol"FAIL);

   if (i)
      return 43;

   printf(OK);

   printf("\nRetype your PASSWORD:");

   if ((i=get_console_passwd(buf+sizeof(buf)/2, sizeof(buf)/2-1))) {

      if (i==13)
         printf("\nMandatory: Retype password");

      printf(FAIL);
      printf("Error in \"get_console_passwd\" %d. Exiting\n", i);

      return i;

   }

   if ((i=f_passwd_comp_safe(buf, buf+sizeof(buf)/2, sizeof(buf)/2, 8, 32))) {

      printf(FAIL);
      printf("Pasword does not match %d\nExiting...\n\n", i);

      return i;

   }

   printf("%s", OK"Generating a Nano SEED ... It can take a little longer. Try to move the mouse, open some programs to increase entropy ...\n");

   if ((i=f_cloud_crypto_wallet_nano_create_seed((size_t)n, filename, buf))) {

      printf("\nError %d: Can't create a Nano SEED."FAIL, i);

      return i;

   }

   printf(OK"File \"%s\" generated successfully. Don't lose your file. If you lose it you will not be able to access your funds.\n", filename);
   printf("\nDon't forget your password. If you forget your password you can not access your funds\n");

   printf(SUCCESS);

   return 0;

}

