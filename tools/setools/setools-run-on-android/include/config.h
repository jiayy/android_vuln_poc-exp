/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* GTK+ is version 2.8+ */
#define GTK_2_8 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `bz2' library (-lbz2). */
#define HAVE_LIBBZ2 1

/* Define to 1 if you have the `selinux' library (-lselinux). */
/* #undef HAVE_LIBSELINUX */

/* Define to 1 if you have the `sepol' library (-lsepol). */
#define HAVE_LIBSEPOL 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `rand_r' function. */
/* #undef HAVE_RAND_R */

/* sepol's new expand boolmap behavior */
#define HAVE_SEPOL_BOOLMAP 1

/* if libsepol has errcodes.h */
#define HAVE_SEPOL_ERRCODES 1

/* if types can be marked as permissive */
#define HAVE_SEPOL_PERMISSIVE_TYPES 1

/* if libsepol has policycaps */
#define HAVE_SEPOL_POLICYCAPS 1

/* if role attributes are supported */
#define HAVE_SEPOL_ROLE_ATTRS 1

/* if users and roles are mapped during policy expansion */
#define HAVE_SEPOL_USER_ROLE_MAPPING 1

/* Define to 1 if stdbool.h conforms to C99. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if the system has the type `_Bool'. */
#define HAVE__BOOL 1

/* libapol version */
#define LIBAPOL_VERSION_STRING "4.4"

/* libpoldiff version */
#define LIBPOLDIFF_VERSION_STRING "1.3.3"

/* libqpol version */
#define LIBQPOL_VERSION_STRING "1.7"

/* libapol version */
#define LIBSEAUDIT_VERSION_STRING "4.5"

/* libsefs version */
#define LIBSEFS_VERSION_STRING "4.0.4"

/* enable libselinux-specific code */
/* #undef LIBSELINUX */

/* link programs using shared libraries */
#define LINK_SHARED 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Are we building against Mac OS X TkAqua? */
/* #undef MAC_OSX_TK */

/* disable calls to assert() */
#define NDEBUG 1

/* Name of package */
#ifndef PACKAGE
#define PACKAGE "setools"
#endif

/* Define to the address where bug reports for this package should be sent. */
#ifndef PACKAGE_BUGREPORT
#define PACKAGE_BUGREPORT "Tresys Technology <setools@tresys.com>"
#endif

/* Define to the full name of this package. */
#ifndef PACKAGE_NAME
#define PACKAGE_NAME "setools"
#endif

/* Define to the full name and version of this package. */
#ifndef PACKAGE_STRING
#define PACKAGE_STRING "setools 3.3.8"
#endif

/* Define to the one symbol short name of this package. */
#ifndef PACKAGE_TARNAME
#define PACKAGE_TARNAME "setools"
#endif

/* Define to the home page for this package. */
#ifndef PACKAGE_URL
#define PACKAGE_URL ""
#endif

/* Define to the version of this package. */
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "3.3.8"
#endif

/* if avtab sizes are calculated dynamically by loader or are hardcoded */
#define SEPOL_DYNAMIC_AVTAB 1

/* remap of libsepol 1.x.x define to 2.x.x */
/* #undef SEPOL_EEXIST */

/* remap of libsepol 1.x.x define to 2.x.x */
/* #undef SEPOL_ENOMEM */

/* maximum policy version supported by libsepol */
#define SEPOL_POLICY_VERSION_MAX 27

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* location of testing policies */
#define TEST_POLICIES "."

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version number of package */
#ifndef VERSION
#define VERSION "3.3.8"
#endif

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* Number of bits in a file offset, on hosts where this is settable. */
#define _FILE_OFFSET_BITS 64

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */
