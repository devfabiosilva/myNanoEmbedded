/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdio.h>
#include <string.h>
#include "f_nano_crypto_util.h"

#define NANO_RAW (int)1
#define NANO_RAW_STR (int)2
#define NANO_REAL_STR (int)3

typedef struct val_t {
   int type;
   void *ptr;
   char *name;
} VAL;

int print_parsed_value(VAL *val)
{
   int err;
   char buf[512];
   const char *p;
   f_uint128_t balance;

   printf("\n\n*********************************************************************");

   switch (val->type) {
      case NANO_RAW:
         err=f_nano_balance_to_str((char *)(p=(const char *)buf), sizeof(buf), NULL, memcpy(balance, val->ptr, sizeof(balance)));
         break;

      case NANO_RAW_STR:
         err=f_nano_parse_raw_str_to_raw128_t(balance, p=(const char *)val->ptr);
         break;

      case NANO_REAL_STR:
         if ((err=f_nano_parse_real_str_to_raw128_t(balance, (const char *)val->ptr))) return err;
         err=f_nano_balance_to_str((char *)(p=(const char *)buf), sizeof(buf), NULL, balance);
         break;

      default:
         err=-1;
   }

   if (err) return err;

   printf("\nParsing \"%s\" to Nano big number raw balance: \"%s\"", val->name, p);
   printf("\n16 Bytes big number raw data in memory in Big Endian \"%s\"", fhex2strv2(buf, balance, sizeof(balance), 1));

   return 0;

}

int main(int argc, char **argv)
{

   int err, i;
   uint8_t buf[512];
   const char *value01="12";
   const char *value02="0.00005102618";
   const char *value03="2729839817722998883998737778887";
   const char *value04="17819.827737766515561562";
   const char *value05="71966199.1772973549018999177254882845";
   const char *value06="00012.00000000000000";
   const unsigned char value07[] = {0x03, 0x16, 0x7f, 0xbf, 0xa3, 0xc1, 0xaa, 0x10, 0x02, 0x87, 0x39, 0x00, 0x8c, 0x00, 0x09, 0x3d};
   VAL values[] = {
      {NANO_REAL_STR, (void *)value01, "value01"},
      {NANO_REAL_STR, (void *)value02, "value02"},
      {NANO_RAW_STR,  (void *)value03, "value03"},
      {NANO_REAL_STR, (void *)value04, "value04"},
      {NANO_REAL_STR, (void *)value05, "value05"},
      {NANO_REAL_STR, (void *)value06, "value06"},
      {NANO_RAW,      (void *)value07, "value07"}
   };

   printf(LICENSE);

   for (i=0;i<(sizeof(values)/sizeof(VAL));i++)
      if ((err=print_parsed_value(&values[i]))) {
         printf("\nError %d in index %d\nAborting ...\n\n", err, i);
         return err;
      }

   printf("\n\nFinally HELLO WORLD !!!\n\n");

   return 0;

}

