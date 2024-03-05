/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     PATH = 258,
     FILENAME = 259,
     CLONE = 260,
     COMMON = 261,
     CLASS = 262,
     CONSTRAIN = 263,
     VALIDATETRANS = 264,
     INHERITS = 265,
     SID = 266,
     ROLE = 267,
     ROLES = 268,
     TYPEALIAS = 269,
     TYPEATTRIBUTE = 270,
     TYPEBOUNDS = 271,
     TYPE = 272,
     TYPES = 273,
     ALIAS = 274,
     ATTRIBUTE = 275,
     BOOL = 276,
     IF = 277,
     ELSE = 278,
     TYPE_TRANSITION = 279,
     TYPE_MEMBER = 280,
     TYPE_CHANGE = 281,
     ROLE_TRANSITION = 282,
     RANGE_TRANSITION = 283,
     SENSITIVITY = 284,
     DOMINANCE = 285,
     DOM = 286,
     DOMBY = 287,
     INCOMP = 288,
     CATEGORY = 289,
     LEVEL = 290,
     RANGE = 291,
     MLSCONSTRAIN = 292,
     MLSVALIDATETRANS = 293,
     USER = 294,
     NEVERALLOW = 295,
     ALLOW = 296,
     AUDITALLOW = 297,
     AUDITDENY = 298,
     DONTAUDIT = 299,
     SOURCE = 300,
     TARGET = 301,
     SAMEUSER = 302,
     FSCON = 303,
     PORTCON = 304,
     NETIFCON = 305,
     NODECON = 306,
     PIRQCON = 307,
     IOMEMCON = 308,
     IOPORTCON = 309,
     PCIDEVICECON = 310,
     FSUSEXATTR = 311,
     FSUSETASK = 312,
     FSUSETRANS = 313,
     FSUSEPSID = 314,
     GENFSCON = 315,
     U1 = 316,
     U2 = 317,
     U3 = 318,
     R1 = 319,
     R2 = 320,
     R3 = 321,
     T1 = 322,
     T2 = 323,
     T3 = 324,
     L1 = 325,
     L2 = 326,
     H1 = 327,
     H2 = 328,
     NOT = 329,
     AND = 330,
     OR = 331,
     XOR = 332,
     CTRUE = 333,
     CFALSE = 334,
     IDENTIFIER = 335,
     NUMBER = 336,
     EQUALS = 337,
     NOTEQUAL = 338,
     IPV4_ADDR = 339,
     IPV6_ADDR = 340,
     MODULE = 341,
     VERSION_IDENTIFIER = 342,
     REQUIRE = 343,
     OPTIONAL = 344,
     POLICYCAP = 345,
     PERMISSIVE = 346
   };
#endif
/* Tokens.  */
#define PATH 258
#define FILENAME 259
#define CLONE 260
#define COMMON 261
#define CLASS 262
#define CONSTRAIN 263
#define VALIDATETRANS 264
#define INHERITS 265
#define SID 266
#define ROLE 267
#define ROLES 268
#define TYPEALIAS 269
#define TYPEATTRIBUTE 270
#define TYPEBOUNDS 271
#define TYPE 272
#define TYPES 273
#define ALIAS 274
#define ATTRIBUTE 275
#define BOOL 276
#define IF 277
#define ELSE 278
#define TYPE_TRANSITION 279
#define TYPE_MEMBER 280
#define TYPE_CHANGE 281
#define ROLE_TRANSITION 282
#define RANGE_TRANSITION 283
#define SENSITIVITY 284
#define DOMINANCE 285
#define DOM 286
#define DOMBY 287
#define INCOMP 288
#define CATEGORY 289
#define LEVEL 290
#define RANGE 291
#define MLSCONSTRAIN 292
#define MLSVALIDATETRANS 293
#define USER 294
#define NEVERALLOW 295
#define ALLOW 296
#define AUDITALLOW 297
#define AUDITDENY 298
#define DONTAUDIT 299
#define SOURCE 300
#define TARGET 301
#define SAMEUSER 302
#define FSCON 303
#define PORTCON 304
#define NETIFCON 305
#define NODECON 306
#define PIRQCON 307
#define IOMEMCON 308
#define IOPORTCON 309
#define PCIDEVICECON 310
#define FSUSEXATTR 311
#define FSUSETASK 312
#define FSUSETRANS 313
#define FSUSEPSID 314
#define GENFSCON 315
#define U1 316
#define U2 317
#define U3 318
#define R1 319
#define R2 320
#define R3 321
#define T1 322
#define T2 323
#define T3 324
#define L1 325
#define L2 326
#define H1 327
#define H2 328
#define NOT 329
#define AND 330
#define OR 331
#define XOR 332
#define CTRUE 333
#define CFALSE 334
#define IDENTIFIER 335
#define NUMBER 336
#define EQUALS 337
#define NOTEQUAL 338
#define IPV4_ADDR 339
#define IPV6_ADDR 340
#define MODULE 341
#define VERSION_IDENTIFIER 342
#define REQUIRE 343
#define OPTIONAL 344
#define POLICYCAP 345
#define PERMISSIVE 346




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 2068 of yacc.c  */
#line 85 "policy_parse.y"

	unsigned int val;
	uintptr_t valptr;
	void *ptr;
        require_func_t require_func;



/* Line 2068 of yacc.c  */
#line 241 "policy_parse.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


