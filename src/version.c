//sat jul 24 14:49:11 -03 2021 
#include <stdint.h>
#include <stdio.h>
#include <version.h>

// 10|11|11
// j-> major ; mN minorN
// j.m1.m2
#define MINOR1 (uint16_t)0
#define MINOR1_STR "0"
#define MINOR2 (uint16_t)1
#define MINOR2_STR "1"
#define MAJOR (uint16_t)0
#define MAJOR_STR "0"
#define VERSION_STR MAJOR_STR"."MINOR2_STR"."MINOR1_STR
#define RELEASE_DATE_STR "202107241422"
#define MYNANOEMBEDDED_VERSION_STR "myNanoEmbedded "VERSION_STR" - "RELEASE_DATE_STR
#define GET_VERSION_U32 (uint32_t)((MAJOR<<22)|(MINOR1<<11)|(MINOR2))

char *getTextInfoVersion()
{
   return MYNANOEMBEDDED_VERSION_STR;
}

char *releaseDateVersion()
{
   return RELEASE_DATE_STR;
}

char *getTextVersion()
{
   return VERSION_STR;
}

uint32_t getVersion()
{
   return GET_VERSION_U32;
}

uint16_t getVersionMinor1()
{
   return MINOR1;
}

uint16_t getVersionMinor2()
{
   return MINOR2;
}

uint16_t getVersionMajor()
{
   return MAJOR;
}

