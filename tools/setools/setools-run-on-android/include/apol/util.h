/**
 * @file
 *
 * Miscellaneous, uncategorized functions for libapol.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2001-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef APOL_UTIL_H
#define APOL_UTIL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "vector.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Return an immutable string describing this library's version.
 *
 * @return String describing this library.
 */
	extern const char *libapol_get_version(void);

/**
 * Given a portcon protocol, return a read-only string that describes
 * that protocol.
 *
 * @param protocol Portcon protocol, one of IPPROTO_TCP or IPPROTO_UDP
 * from netinet/in.h.
 *
 * @return A string that describes the protocol, or NULL if the
 * protocol is invalid.  <b>Do not free() this string.</b>
 */
	extern const char *apol_protocol_to_str(uint8_t protocol);

/**
 * Given the name of a portcon protocol, return its numeric value.
 *
 * @param protocol_str Portcon protocol, one of "tcp", "TCP", "udp", or "UDP".
 *
 * @return Numeric value for the protocol, one of IPPROTO_TCP or IPPROTO_UDP
 * from netinet/in.h.  Upon error return 0.
 */
	extern uint8_t apol_str_to_protocol(const char *protocol_str);

/**
 * Given a string representing and IP value (mask or address, IPv4 or
 * IPv6), write to an array that value in the same bit order that
 * qpol uses.  If the IP was in IPv4 format, only write to the first
 * element and zero the remainder.
 *
 * @param str A string representing and IP value, either in IPv4 or
 * IPv6 format.
 * @param ip Array to which write converted value.
 *
 * @return QPOL_IPV4 if the string is in IPv4 format, QPOL_IPV6 if
 * in IPv6, < 0 on error.
 */
	extern int apol_str_to_internal_ip(const char *str, uint32_t ip[4]);

/**
 * Given a genfscon object class, return a read-only string that
 * describes that class.
 *
 * @param objclass Object class, one of QPOL_CLASS_BLK_FILE,
 * QPOL_CLASS_CHR_FILE, etc.
 *
 * @return A string that describes the object class, or NULL if the
 * object class is invalid.  <b>Do not free() this string.</b>
 *
 * @see <qpol/genfscon_query.h> for a list of valid object classes.
 */
	extern const char *apol_objclass_to_str(uint32_t objclass);

/**
 * Given a string representing a genfscon object class, return its
 * numeric identifier.  Valid strings may be obtained by calling
 * apol_objclass_to_str().
 *
 * @param objclass Object class, one of "any", "file", etc.
 *
 * @return Numeric identifier for object class, or 0 if unknown.
 *
 * @see <qpol/genfscon_query.h> for a list of valid object classes.
 */
	extern uint32_t apol_str_to_objclass(const char *objclass);

/**
 * Given a fs_use behavior type, return a read-only string that
 * describes that fs_use behavior.
 *
 * @param behavior A fs_use behavior, one of QPOL_FS_USE_PSID,
 * QPOL_FS_USE_XATTR, etc.
 *
 * @return A string that describes the behavior, or NULL if the
 * behavior is invalid.  <b>Do not free() this string.</b>
 */
	extern const char *apol_fs_use_behavior_to_str(uint32_t behavior);

/**
 * Given a fs_use behavior string, return its numeric value.
 *
 * @param behavior A fs_use behavior, one of "fs_use_psid",
 * "fs_use_xattr", etc.
 *
 * @return A numeric representation for the behavior, one of
 * QPOL_FS_USE_PSID, QPOL_FS_USE_XATTR, etc, or < 0 if the string is
 * invalid.
 */
	extern int apol_str_to_fs_use_behavior(const char *behavior);

/**
 * Given a rule type, return a read-only string that describes that
 * rule.
 *
 * @param rule_type A policy rule type, one of QPOL_RULE_ALLOW,
 * QPOL_RULE_TYPE_CHANGE, etc.
 *
 * @return A string that describes the rule, or NULL if the rule_type
 * is invalid.  <b>Do not free() this string.</b>
 */
	extern const char *apol_rule_type_to_str(uint32_t rule_type);

/**
 * Given a conditional expression type, return a read-only string that
 * describes that operator.
 *
 * @param expr_type An expression type, one of QPOL_COND_EXPR_BOOL,
 * QPOL_COND_EXPR_NOT, etc.
 *
 * @return A string that describes the expression, or NULL if the
 * expr_type is invalid.  <b>Do not free() this string.</b>
 */
	extern const char *apol_cond_expr_type_to_str(uint32_t expr_type);

/**
 * Given a file name, search and return that file's path on the
 * running system.  First search the present working directory, then
 * the directory at APOL_INSTALL_DIR (an environment variable), then
 * apol's install dir.
 *
 * @param file_name File to find.
 *
 * @return File's path, or NULL if not found.  Caller must free() this
 * string afterwards.
 */
	extern char *apol_file_find(const char *file_name);

/**
 * Given a file name, search and return that file's full path
 * (directory + file name) on the running system.  First search the
 * present working directory, then the directory at APOL_INSTALL_DIR
 * (an environment variable), then apol's install dir.
 *
 * @param file_name File to find.
 *
 * @return File's path + file name, or NULL if not found.  Caller must
 * free() this string afterwards.
 */
	extern char *apol_file_find_path(const char *file_name);

/**
 * Given a file name for a user configuration, search and return that
 * file's path + file name in the user's home directory.
 *
 * @param file_name File to find.
 *
 * @return File's path + file name, or NULL if not found.  Caller must
 * free() this string afterwards.
 */
	extern char *apol_file_find_user_config(const char *file_name);

/**
 * Given a file name, read the file's contents into a newly allocated
 * buffer.  The caller must free() this buffer afterwards.
 *
 * @param fname Name of file to read.
 * @param buf Reference to a newly allocated buffer.
 * @param len Reference to the number of bytes read.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_file_read_to_buffer(const char *fname, char **buf, size_t * len);
/**
 * Given a file pointer into a config file, read and return the value
 * for the given config var.  The caller must free() the returned
 * string afterwards.
 *
 * @param var Name of configuration variable to obtain.
 * @param fp An open file pointer into a configuration file.  This
 * function will not maintain the pointer's current location.
 *
 * @return A newly allocated string containing the variable's value,
 * or NULL if not found or error.
 */
	extern char *apol_config_get_var(const char *var, FILE * fp);

/**
 * Given a string of tokens, allocate and return a vector of strings
 * initialized to those tokens.
 *
 * @param s String to split.
 * @param delim Delimiter for tokens, as per strsep(3).
 *
 * @return A newly allocated vector of strings containing the
 * variable's values, or NULL if not found or error.  Note that the
 * vector could be empty if the config var does not exist or has an
 * empty value.  The caller must call apol_vector_destroy()
 * afterwards.
 */
	extern apol_vector_t *apol_str_split(const char *s, const char *delim);

/**
 * Given a vector of strings, allocate and return a string that joins
 * the vector using the given separator.  The caller is responsible
 * for free()ing the string afterwards.
 *
 * @param list Vector of strings to join.
 * @param delim Delimiter character(s) for the concatenated string.
 *
 * @return An allocated concatenated string, or NULL upon error.  If
 * the list is empty then return an empty string.  The caller is
 * responsible for calling free() upon the return value.
 */
	extern char *apol_str_join(const apol_vector_t * list, const char *delim);

/**
 * Given a mutable string, modify the string by removing both starting
 * and trailing whitespace characters.
 *
 * @param str String to modify.
 */
	extern void apol_str_trim(char *str);

/**
 * Append a string to an existing dynamic mutable string, expanding
 * the target string if necessary.  The caller must free() the target
 * string.  If tgt is NULL then initially allocate the resulting
 * string.
 *
 * @param tgt Reference to a string to modify, or NULL to create a new
 * string.
 * @param tgt_sz Pointer to number of bytes currently allocated to
 * tgt.  This will be updated with the new string size.  If *tgt is
 * NULL then this existing value is ignored.  (It will still be updated
 * afterwards).
 * @param str String to append.
 *
 * @return 0 on success.  On error, return < 0 and set errno; tgt will be
 * free()d and set to NULL, tgt_sz will be set to 0.
 */
	extern int apol_str_append(char **tgt, size_t * tgt_sz, const char *str);

/**
 * Append a string to an existing dynamic mutable string, expanding
 * the target string if necessary.  The string to append is computed
 * using the format string, as per printf(3).  The caller must free()
 * the target string.  If tgt is NULL then initially allocate the
 * resulting string.
 *
 * @param tgt Reference to a string to modify, or NULL to create a new
 * string.
 * @param tgt_sz Pointer to number of bytes currently allocated to
 * tgt.  This will be updated with the new string size.  If *tgt is
 * NULL then the existing value is ignored.  (It will still be updated
 * afterwards).
 * @param fmt Format for the string with which append, as per
 * printf(3).
 *
 * @return 0 on success.  On error, return < 0 and set errno; tgt will be
 * free()d and set to NULL, tgt_sz will be set to 0.
 */
	extern int apol_str_appendf(char **tgt, size_t * tgt_sz, const char *fmt, ...);

/* declaration duplicated below to satisfy doxygen */
	extern int apol_str_appendf(char **tgt, size_t * tgt_sz, const char *fmt, ...) __attribute__ ((format(printf, 3, 4)));

/**
 * Test whether a given string is only white space.
 *
 * @param str String to test.
 * @return 1 if string is either NULL or only whitespace, 0 otherwise.
 */
	extern int apol_str_is_only_white_space(const char *str);

/**
 * Wrapper around strcmp for use in vector and BST comparison functions.
 *
 * @param a String to compare.
 * @param b The other string to compare.
 * @param unused Not used. (exists to match expected function signature)
 *
 * @return Less than, equal to, or greater than 0 if string a is found
 * to be less than, identical to, or greater than string b
 * respectively.
 */
	extern int apol_str_strcmp(const void *a, const void *b, void *unused __attribute__ ((unused)));

/**
 * Wrapper around strdup for use in vector and BST cloning functions.
 *
 * @param elem String to duplicate.
 * @param unused Not used. (exists to match expected function signature)
 *
 * @return A new string that is a duplicate of elem, or NULL upon error.
 */
	extern void *apol_str_strdup(const void *elem, void *unused __attribute__ ((unused)));

#ifdef	__cplusplus
}
#endif

#endif
