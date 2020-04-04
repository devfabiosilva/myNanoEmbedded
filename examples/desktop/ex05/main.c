/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdio.h>
#include <string.h>
#include "f_nano_crypto_util.h"

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

   int err;
   char *p;
   uint32_t entropy_mode;
   uint8_t buf[1024];
   NANO_SEED SEED;
   const char *password_memory="abc@1234567890";
   const char *password_file="aW?#183HxKm>@hn-:QV/";
   const char *filename="example.nse";

   printf(LICENSE);
   printf("\n\tThis example we will use \"f_parse_nano_seed_and_bip39_to_JSON\" function to parse a\n\
encrypted block in memory with pass \"%s\" in non determistic mode and decrypt it\n\
and parse SEED and Bip39 to JSON format\n", password_memory);
   printf("\nAlso it will use your PRNG/TRNG to create a random SEED and parse it to JSON as well\n");
   printf("\nFinally we will open encrypted file example \"example.nse\" with password \"%s\" and parse it to JSON.\n", password_file);
   printf("\n\n\nWARNING:\n\nDon't use SEED and Bip39 in \"example.nse\"\n\nPRESS ANY KEY TO CONTINUE ...");
   f_get_char_no_block(F_GET_CH_MODE_ANY_KEY);
   printf("\n\nChoose one entropy type:\n\n\t1-PARANOIC (Very best but very slow)\n\t2-EXCELENT (Best but slow)\n\t3-GOOD (Normal)\n\t4-NOT ENOUGH (Not so good)\
\n\t5-NOT RECOMENDED (Not recommended but fast)\n\n\tOr \"q\" to QUIT\nCHOICE:");

   for (;;) {

      if ((err=f_get_char_no_block(F_GET_CH_MODE_ANY_KEY))==(int)'q') {

         printf("\nExiting...\n\n");
         return 0;

      }

      if (entropy_mode=f_sel_to_entropy_level(err))
         break;

      printf("\nInvalid option. Choose a number between 1 and 5 or press \"q\" to QUIT.");

   }

   printf("\nAtatching random number generator function...\n");

   f_random_attach(gen_rand_no_entropy);

   printf("\nGenerating a random Nano SEED with selected entropy: %s", (p=f_get_entropy_name(entropy_mode)));
   printf("\nIt can take a little longer. Move mouse, open programs to increase entropy\n");

   if (err=f_generate_nano_seed(SEED, entropy_mode)) {

      printf("\nError \"f_generate_nano_seed\" %d\nCould not generate SEED. Aborting ...\n", err);

      return err;

   }

   printf("\nSEED \"%s\" successfully generated. (DON'T TELL IT TO ANYBODY).\n", f_nano_key_to_str(buf, SEED));

   printf("Parsing generated Nano SEED \"%s\" to JSON...\n", buf);

   if ((err=f_parse_nano_seed_and_bip39_to_JSON(buf, sizeof(buf), NULL, (void *)SEED, PARSE_JSON_READ_SEED_GENERIC, NULL))) {

      printf("Error when parse Nano SEED to JSON %d\nAborting ...\n\n", err);

      return err;

   }

   printf("\nValue parsed to JSON = \"%s\"\n", buf);

   printf("Generating a new SEED with with entropy mode \"%s\" and encrypting in memory with password \"%s\"...\n", p, password_memory);
   printf("\nTaking more a little longer... Wait...\n\n");

   if (err=f_generate_nano_seed(SEED, entropy_mode)) {

      printf("\nError \"f_generate_nano_seed\" %d\nCould not generate second SEED. Aborting ...\n", err);

      return err;

   }

   printf("Nano SEED generated successfully\nEncrypting Nano SEED ...\n");

   if ((err=f_write_seed((void *)buf, WRITE_SEED_TO_STREAM, SEED, (char *)password_memory))) {

      printf("Error in \"f_write_seed\" when encrypting to memory block. Aborting... %d\n\n", err);

      return err;

   }

   printf("Cleaning plaintext SEED from memory...\n");
   memset(SEED, 0, sizeof(SEED));

   printf("Success. Encrypted block stream stored at position in memory %p with encrypted data stream \"%s\"\n with total size %ld bytes",
      buf+offsetof(F_NANO_CRYPTOWALLET, seed_block),
      fhex2strv2(buf+sizeof(F_NANO_CRYPTOWALLET),
      buf+offsetof(F_NANO_CRYPTOWALLET, seed_block),
      sizeof(F_ENCRYPTED_BLOCK), 0),
      sizeof(F_NANO_CRYPTOWALLET));

   printf("\nPress \"c\" key to continue ...");

   f_get_char_no_block(F_GET_CH_MODE_NO_ECHO|(int)'c');

   printf("\n\n\nContinuing... decrypting stream block in memory region %p\n", buf);

   if ((err=f_parse_nano_seed_and_bip39_to_JSON(buf+sizeof(F_NANO_CRYPTOWALLET), sizeof(buf)-sizeof(F_NANO_CRYPTOWALLET), NULL, (void *)buf,
      READ_SEED_FROM_STREAM, password_memory))) {

      printf("\nError when read encrypted stream from memory position %p with error number %d\n\nAborting ...\n\n", buf, err);

      return err;

   }

   printf("\nNano SEED extracted with success !!!\n\nParsing to JSON ...\nJSON = \"%s\"\n\n", buf+sizeof(F_NANO_CRYPTOWALLET));
   printf("\n\nNext it will open \"%s\" Nano SEED example file (*.nse) encrypted with password \"%s\". Don't use this SEED in this file. It's a example\n\n",
      filename, password_file);

   printf("\nPress \"c\" key to continue ...");

   f_get_char_no_block(F_GET_CH_MODE_NO_ECHO|(int)'c');

   printf("\n\n\nContinuing... decrypting file \"%s\" ...", filename);

   if ((err=f_parse_nano_seed_and_bip39_to_JSON(buf, sizeof(buf), NULL, (void *)filename, READ_SEED_FROM_FILE, password_file))) {

      printf("\nError when read encrypted file \"%s\" error number %d\n\nAborting ...\n\n", filename, err);

      return err;

   }

   printf("\n\nFile \"%s\" decrypted successfully ;)\n\nJSON =  \"%s\"\n\n", filename, buf);

   printf("\n\nFinally HELLO WORLD !!!\n\n");

   return 0;

}

