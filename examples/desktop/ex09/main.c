/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdio.h>
#include <string.h>
#include "f_nano_crypto_util.h"

#define USAGE "\nThis example calculate a Proof of Work of a given hash and threshold difficulty\
\n\n\nUSAGE\n\
=====\n\n\
\texample9 [auto|hash <HASH VALUE>] n <NUMBER OF THREADS> t <THRESHOLD VALUE>(OPTIONAL)\
\n\n"

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

   int err, i, n_thr;
   uint8_t buf[256];
   unsigned char hash[32], *p, *p_hash;
   uint64_t pow, result, threshold;

   if (argc==1) {

      printf(LICENSE);
      printf(USAGE);

      return 0;

   }

   threshold=0xffffffc000000000;
   n_thr=0;
   p_hash=NULL;

   printf("\nAttaching random function to \"myNanoEmbedded\" API ...\n");
   f_random_attach(gen_rand_no_entropy);

   for (i=1;i<argc;) {

      if (strcmp("auto", (const char *)(p=(unsigned char *)argv[i++]))==0) {

         if (argc>6) {

            printf("\nError: Too many arguments in auto hash generator\n\n");

            return 30;

         }

         if (argc<4) {

            printf("\nERROR: Missing number of threads in auto hash generator\n\n");

            return 31;

         }

         f_random((void *)(p_hash=hash), sizeof(hash));

         printf("\nRandom hash generated: \"%s\"\n", f_nano_key_to_str(buf, hash));

         continue;

      }

      if (strcmp("n", (const char *)p)==0) {

         if (i==argc) {

            printf("\nError: Missing thread value\n\n");

            return 25;

         }

         if (!f_is_integer((char *)(p=(unsigned char *)argv[i++]), 3)) {

            printf("\nERROR: Number of threads is not an integer value or has an invalid length\n\n");

            return 22;

         }

         if (f_convert_to_unsigned_int((unsigned int *)&n_thr, (char *)p, 3)) {

            printf("\n\nError. Parsing number of threads to int\n\n");

            return 23;

         }

         continue;

      }

      if (strcmp("hash", (const char *)p)==0) {

         if (i==argc) {

            printf("\nError: Missing \"hash\"\n");

            return 26;

         }

         if (argc>7) {

            printf("\nError: Too many arguments in \"hash\" POW\n\n");

            return 27;

         }

         if (argc<4) {

            printf("\nFew arguments in \"hash\" POW. Needed number of threads\n\n");

            return 28;

         }

         if (strnlen((const char *)(p=(unsigned char *)argv[i++]), 65)!=64) {

            printf("\n\nERROR: Hash value should have 32 bytes in length\n\n");

            return 29;

         }

         if ((err=f_str_to_hex((uint8_t *)(p_hash=hash), (char *)p))) {

            printf("\nError when converting ASCII HEX to raw binary %d\n", err);

            return 30;

         }

         continue;

      }

      if (strcmp("t", (const char *)p)==0) {

         if (i==argc) {

            printf("\nERROR: Missing threshold value\n\n");

            return 31;

         }

         if ((err=f_convert_to_long_int_std(&threshold, (char *)(p=(unsigned char *)argv[i++]), 23))) {

            printf("\nError when parsing value \"%s\" to long int %d\n\n", (char *)p, err);

            return err;

         }

         continue;

      }


      printf("\nInvalid command: \"%s\"\n", (const char *)p);

      return 21;

   }

   if (!p_hash) {

      printf("\nError: Required hash value or random hash\n\n");

      return 42;

   }

   if (n_thr>F_NANO_POW_MAX_THREAD) {

      printf("\nError: Maximum number of thread \"%d\" is greater than \"F_NANO_POW_MAX_THREAD\". Please modify it in \"f_nano_crypto_util.h\"\n\n", n_thr);

      return 40;

   } else if (n_thr==0) {

      printf("\nError. Invalid thread number. It cannot be ZERO !!\n\n");

      return 41;

   }

   printf("\nGenerating a Proof of Work given threshold \"%016lx\" ... Please, wait ...\n", threshold);

   if ((err=f_nano_pow(&pow, hash, threshold, n_thr))) {

      printf("\nError in \"f_nano_pow\" %d\n", err);

      return err;

   }

   if ((err=f_verify_work(&result, hash, &pow, threshold))>0) {

      err=0;
      printf("\nSuccess. Work \"%016lx\" value produces a hash \"%016lx\"\n", pow, result);

   } else if (err) {

      printf("\nInternal error %d\n", err);

      return err;

   } else {

      printf("\nWork did not pass the test\n");

      return 120;

   }

   printf("\n\nFinally HELLO WORLD !!!\n\n");

   return err;

}

