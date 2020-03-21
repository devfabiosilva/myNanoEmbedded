/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdint.h>

/**
 * @file
 * @brief Low level implementation of Nano Cryptocurrency C library 
 */

/**
 * @typedef F_ADD_288
 * @brief 288 bit big number
 */
typedef uint8_t F_ADD_288[36];


#ifndef F_DOC_SKIP

/**
 * @fn f_add_bn_288_le(F_ADD_288 X, F_ADD_288 Y, F_ADD_288 RES, int *carry_out, int carry_in);
 * @brief Adds two big numbers of size 288 bits. This function is implemented in low level for API use. It performs RES = X + Y + carry_in
 * @param [in] X Big number 288 bit X value
 * @param [in] Y Big number 288 bit Y value
 * @param [out] RES Big number 288 bit result RES value
 * @param [out] carry_out Carry out. It can be NULL if you want to omit <i>carry_out</i>
 * @param [in] carry_in Carry in (borrow) of last sum. Parse 0 to omit.
 */
 void f_add_bn_288_le(F_ADD_288, F_ADD_288, F_ADD_288, int *, int);
 void f_sl_elv_add_le(F_ADD_288, int);

#endif

