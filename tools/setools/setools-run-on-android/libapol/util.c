/**
 * @file
 *
 * Implementation of utility functions.
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

#include <config.h>

#include <apol/util.h>

#include <assert.h>
#include <byteswap.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

/* these are needed for nodecons and IPv4 and IPv6 */
#include <qpol/nodecon_query.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>		       /* needed for portcon's protocol */

#define APOL_INSTALL_DIR "/"

/* use 8k line size */
#define APOL_LINE_SZ 8192
#define APOL_ENVIRON_VAR_NAME "APOL_INSTALL_DIR"

void swab1(const void *from, void *to, ssize_t n)
{
	uint16_t *tmp = (uint16_t *)to;
	int i;

	n >>= 1;
	for (i = 0; i < n; i++) {
		tmp[i] = bswap_16(((uint16_t *)from)[i]);
	}
}

const char *libapol_get_version(void)
{
	return LIBAPOL_VERSION_STRING;
}

int apol_str_to_internal_ip(const char *str, uint32_t ip[4])
{
	bool ipv4 = false;
	bool ipv6 = false;

	if (!str || !ip) {
		errno = EINVAL;
		return -1;
	}

	ip[0] = ip[1] = ip[2] = ip[3] = 0;

	if (strchr(str, '.'))
		ipv4 = true;

	if (strchr(str, ':'))
		ipv6 = true;

	if (ipv4 == ipv6) {
		errno = EINVAL;
		return -1;
	}

	if (ipv4) {
		unsigned char *p = (unsigned char *)&(ip[0]);
		int seg = 0;
		uint32_t val = 0;      /* value of current segment of address */
		size_t len = strlen(str), i;
		for (i = 0; i <= len; i++) {
			if (str[i] == '.' || str[i] == '\0') {
				if (val > 255) {
					errno = EINVAL;
					return -1;
				}

				p[seg] = (unsigned char)(0xff & val);
				seg++;
				val = 0;
				if (seg == 4)
					break;
			} else if (isdigit(str[i])) {
				char tmp[2] = { str[i], 0 };
				val = val * 10 + atoi(tmp);
			} else {
				errno = EINVAL;
				return -1;
			}
		}
	} else {
		struct in6_addr addr;
		if (inet_pton(AF_INET6, str, &addr) <= 0) {
			return -1;
		}
		memcpy(ip, addr.s6_addr32, 16);
	}

	return ipv4 ? QPOL_IPV4 : QPOL_IPV6;
}

const char *apol_objclass_to_str(uint32_t objclass)
{
	switch (objclass) {
	case QPOL_CLASS_BLK_FILE:
		return "block";
	case QPOL_CLASS_CHR_FILE:
		return "char";
	case QPOL_CLASS_DIR:
		return "dir";
	case QPOL_CLASS_FIFO_FILE:
		return "fifo";
	case QPOL_CLASS_FILE:
		return "file";
	case QPOL_CLASS_LNK_FILE:
		return "link";
	case QPOL_CLASS_SOCK_FILE:
		return "sock";
	case QPOL_CLASS_ALL:
		return "any";
	}
	return NULL;
}

uint32_t apol_str_to_objclass(const char *objclass)
{
	if (objclass == NULL) {
		errno = EINVAL;
		return 0;
	}
	if (strcmp(objclass, "block") == 0) {
		return QPOL_CLASS_BLK_FILE;
	}
	if (strcmp(objclass, "char") == 0) {
		return QPOL_CLASS_CHR_FILE;
	}
	if (strcmp(objclass, "dir") == 0) {
		return QPOL_CLASS_DIR;
	}
	if (strcmp(objclass, "fifo") == 0) {
		return QPOL_CLASS_FIFO_FILE;
	}
	if (strcmp(objclass, "file") == 0) {
		return QPOL_CLASS_FILE;
	}
	if (strcmp(objclass, "link") == 0) {
		return QPOL_CLASS_LNK_FILE;
	}
	if (strcmp(objclass, "sock") == 0) {
		return QPOL_CLASS_SOCK_FILE;
	}
	if (strcmp(objclass, "any") == 0) {
		return QPOL_CLASS_ALL;
	}
	return 0;
}

const char *apol_protocol_to_str(uint8_t protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	default:
		errno = EPROTONOSUPPORT;
		return NULL;
	}
}

uint8_t apol_str_to_protocol(const char *protocol_str)
{
	if (protocol_str == NULL) {
		errno = EINVAL;
		return 0;
	}
	if (strcmp(protocol_str, "tcp") == 0 || strcmp(protocol_str, "TCP") == 0) {
		return IPPROTO_TCP;
	}
	if (strcmp(protocol_str, "udp") == 0 || strcmp(protocol_str, "UDP") == 0) {
		return IPPROTO_UDP;
	}
	errno = EPROTONOSUPPORT;
	return 0;
}

const char *apol_fs_use_behavior_to_str(uint32_t behavior)
{
	switch (behavior) {
	case QPOL_FS_USE_XATTR:
		return "fs_use_xattr";
	case QPOL_FS_USE_TASK:
		return "fs_use_task";
	case QPOL_FS_USE_TRANS:
		return "fs_use_trans";
	case QPOL_FS_USE_GENFS:
		return "fs_use_genfs";
	case QPOL_FS_USE_NONE:
		return "fs_use_none";
	case QPOL_FS_USE_PSID:
		return "fs_use_psid";
	}
	return NULL;
}

int apol_str_to_fs_use_behavior(const char *behavior)
{
	if (strcmp(behavior, "fs_use_xattr") == 0) {
		return QPOL_FS_USE_XATTR;
	} else if (strcmp(behavior, "fs_use_task") == 0) {
		return QPOL_FS_USE_TASK;
	} else if (strcmp(behavior, "fs_use_trans") == 0) {
		return QPOL_FS_USE_TRANS;
	} else if (strcmp(behavior, "fs_use_genfs") == 0) {
		return QPOL_FS_USE_GENFS;
	} else if (strcmp(behavior, "fs_use_none") == 0) {
		return QPOL_FS_USE_NONE;
	} else if (strcmp(behavior, "fs_use_psid") == 0) {
		return QPOL_FS_USE_PSID;
	}
	return -1;
}

const char *apol_rule_type_to_str(uint32_t rule_type)
{
	switch (rule_type) {
	case QPOL_RULE_ALLOW:
		return "allow";
	case QPOL_RULE_NEVERALLOW:
		return "neverallow";
	case QPOL_RULE_AUDITALLOW:
		return "auditallow";
	case QPOL_RULE_DONTAUDIT:
		return "dontaudit";
	case QPOL_RULE_TYPE_TRANS:
		return "type_transition";
	case QPOL_RULE_TYPE_CHANGE:
		return "type_change";
	case QPOL_RULE_TYPE_MEMBER:
		return "type_member";
	}
	return NULL;
}

const char *apol_cond_expr_type_to_str(uint32_t expr_type)
{
	switch (expr_type) {
	case QPOL_COND_EXPR_BOOL:
		return "";
	case QPOL_COND_EXPR_NOT:
		return "!";
	case QPOL_COND_EXPR_OR:
		return "||";
	case QPOL_COND_EXPR_AND:
		return "&&";
	case QPOL_COND_EXPR_XOR:
		return "^";
	case QPOL_COND_EXPR_EQ:
		return "==";
	case QPOL_COND_EXPR_NEQ:
		return "!=";
	}
	return NULL;
}

char *apol_file_find(const char *file_name)
{
	char *file = NULL, *var = NULL, *dirs[3];
	size_t i;
	int rt;

	if (file_name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* check current directory, environment variable, and then
	 * installed directory */
	dirs[0] = ".";
	dirs[1] = getenv(APOL_ENVIRON_VAR_NAME);
	dirs[2] = APOL_INSTALL_DIR;
	for (i = 0; i < 3; i++) {
		if ((var = dirs[i]) != NULL) {
			if (asprintf(&file, "%s/%s", var, file_name) < 0) {
				return NULL;
			}
			rt = access(file, R_OK);
			free(file);
			if (rt == 0) {
				return strdup(var);
			}
		}
	}

	/* didn't find it */
	return NULL;
}

char *apol_file_find_path(const char *file_name)
{
	char *file = NULL, *var = NULL, *dirs[3];
	size_t i;
	int rt;

	if (file_name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* check current directory, environment variable, and then
	 * installed directory */
	dirs[0] = ".";
	dirs[1] = getenv(APOL_ENVIRON_VAR_NAME);
	dirs[2] = APOL_INSTALL_DIR;
	for (i = 0; i < 3; i++) {
		if ((var = dirs[i]) != NULL) {
			if (asprintf(&file, "%s/%s", var, file_name) < 0) {
				return NULL;
			}
			rt = access(file, R_OK);
			if (rt == 0) {
				return file;
			}
			free(file);
		}
	}

	/* didn't find it */
	return NULL;
}

char *apol_file_find_user_config(const char *file_name)
{
	char *file, *var;
	int rt;

	if (file_name == NULL) {
		errno = EINVAL;
		return NULL;
	}
	var = getenv("HOME");
	if (var) {
		if (asprintf(&file, "%s/%s", var, file_name) < 0) {
			return NULL;
		}
		rt = access(file, R_OK);
		if (rt == 0) {
			return file;
		} else {
			free(file);
			return NULL;
		}
	}
	return NULL;
}

int apol_file_read_to_buffer(const char *fname, char **buf, size_t * len)
{
	FILE *file = NULL;
	const size_t BUF_SIZE = 1024;
	size_t size = 0, r;
	char *bufp, *b;

	assert(*buf == NULL);
	assert(len);
	*len = 0;
	while (1) {
		size += BUF_SIZE;
		r = 0;
		b = (char *)realloc(*buf, size * sizeof(char));
		if (b == NULL) {
			free(*buf);
			*buf = NULL;
			*len = 0;
			if (file)
				fclose(file);
			return -1;
		}
		*buf = b;
		if (!file) {
			file = fopen(fname, "rb");
			if (!file) {
				free(*buf);
				*buf = NULL;
				*len = 0;
				return -1;
			}
		}
		bufp = &((*buf)[size - BUF_SIZE]);
		r = fread(bufp, sizeof(char), BUF_SIZE, file);
		*len += r;
		if (r < BUF_SIZE) {
			if (feof(file)) {
				fclose(file);
				break;
			} else {
				free(*buf);
				*buf = NULL;
				*len = 0;
				fclose(file);
				return -1;
			}
		}
	}
	return 0;
}

char *apol_config_get_var(const char *var, FILE * fp)
{
	char line[APOL_LINE_SZ], t1[APOL_LINE_SZ], t2[APOL_LINE_SZ];
	char *line_ptr = NULL;

	if (var == NULL || fp == NULL) {
		errno = EINVAL;
		return NULL;
	}

	rewind(fp);
	while (fgets(line, APOL_LINE_SZ, fp) != NULL) {
		if ((line_ptr = strdup(line)) == NULL) {
			return NULL;
		}
		apol_str_trim(line_ptr);
		if (line_ptr[0] == '#' || sscanf(line_ptr, "%s %[^\n]", t1, t2) != 2 || strcasecmp(var, t1) != 0) {
			free(line_ptr);
			continue;
		} else {
			free(line_ptr);
			return strdup(t2);
		}
	}
	return NULL;
}

apol_vector_t *apol_str_split(const char *s, const char *delim)
{
	char *orig_s = NULL, *dup_s = NULL, *v, *token;
	apol_vector_t *list = NULL;
	int error = 0;

	if (s == NULL || delim == NULL) {
		error = EINVAL;
		goto cleanup;
	}
	if ((list = apol_vector_create(free)) == NULL || (orig_s = strdup(s)) == NULL) {
		error = errno;
		goto cleanup;
	}
	v = orig_s;
	while ((token = strsep(&v, delim)) != NULL) {
		if (strcmp(token, "") != 0 && !apol_str_is_only_white_space(token)) {
			if ((dup_s = strdup(token)) == NULL || apol_vector_append(list, dup_s) < 0) {
				error = errno;
				free(dup_s);
				goto cleanup;
			}
		}
	}
      cleanup:
	free(orig_s);
	if (error != 0) {
		apol_vector_destroy(&list);
		errno = error;
		return NULL;
	}
	return list;
}

char *apol_str_join(const apol_vector_t * list, const char *delim)
{
	char *val, *s;
	size_t i, len;

	if (list == NULL || delim == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (apol_vector_get_size(list) == 0) {
		return strdup("");
	}
	s = apol_vector_get_element(list, 0);
	if ((val = strdup(s)) == NULL) {
		return NULL;
	}
	len = strlen(val) + 1;
	for (i = 1; i < apol_vector_get_size(list); i++) {
		s = apol_vector_get_element(list, i);
		if (apol_str_appendf(&val, &len, "%s%s", delim, s) < 0) {
			return NULL;
		}
	}
	return val;
}

/**
 * Given a string, if the string begins with whitespace then allocate
 * a new string that does not contain those whitespaces.
 *
 * @param str String to modify.
 */
static void trim_leading_whitespace(char *str)
{
	size_t i, len;
	for (i = 0; str[i] != '\0' && isspace(str[i]); i++) ;
	len = strlen(str + i);
	memmove(str, str + i, len + 1);
}

/**
 * Given a mutable string, replace trailing whitespace characters with
 * null characters.
 *
 * @param str String to modify.
 */
static void trim_trailing_whitespace(char *str)
{
	size_t length;
	length = strlen(str);
	while (length > 0 && isspace(str[length - 1])) {
		str[length - 1] = '\0';
		length--;
	}
}

void apol_str_trim(char *str)
{
	if (str == NULL) {
		errno = EINVAL;
		return;
	}
	trim_leading_whitespace(str);
	trim_trailing_whitespace(str);
}

int apol_str_append(char **tgt, size_t * tgt_sz, const char *str)
{
	size_t str_len;
	if (str == NULL || (str_len = strlen(str)) == 0)
		return 0;
	if (tgt == NULL) {
		errno = EINVAL;
		return -1;
	}
	str_len++;
	/* target is currently empty */
	if (*tgt == NULL || *tgt_sz == 0) {
		*tgt = (char *)malloc(str_len);
		if (*tgt == NULL) {
			*tgt_sz = 0;
			return -1;
		}
		*tgt_sz = str_len;
		strcpy(*tgt, str);
		return 0;
	} else {
		/* tgt has some memory */
		char *t = (char *)realloc(*tgt, *tgt_sz + str_len);
		if (t == NULL) {
			int error = errno;
			free(*tgt);
			*tgt = NULL;
			*tgt_sz = 0;
			errno = error;
			return -1;
		}
		*tgt = t;
		*tgt_sz += str_len;
		strcat(*tgt, str);
		return 0;
	}
}

int apol_str_appendf(char **tgt, size_t * tgt_sz, const char *fmt, ...)
{
	va_list ap;
	int error;
	if (fmt == NULL || strlen(fmt) == 0)
		return 0;
	if (tgt == NULL) {
		errno = EINVAL;
		return -1;
	}
	va_start(ap, fmt);
	/* target is currently empty */
	if (*tgt == NULL || *tgt_sz == 0) {
		if (vasprintf(tgt, fmt, ap) < 0) {
			error = errno;
			*tgt = NULL;
			*tgt_sz = 0;
			va_end(ap);
			errno = error;
			return -1;
		}
		*tgt_sz = strlen(*tgt) + 1;
		va_end(ap);
		return 0;
	} else {
		/* tgt has some memory */
		char *t, *u;
		size_t str_len;
		if (vasprintf(&t, fmt, ap) < 0) {
			error = errno;
			free(*tgt);
			*tgt_sz = 0;
			va_end(ap);
			errno = error;
			return -1;
		}
		va_end(ap);
		str_len = strlen(t);
		if ((u = (char *)realloc(*tgt, *tgt_sz + str_len)) == NULL) {
			error = errno;
			free(t);
			free(*tgt);
			*tgt_sz = 0;
			errno = error;
			return -1;
		}
		*tgt = u;
		*tgt_sz += str_len;
		strcat(*tgt, t);
		free(t);
		return 0;
	}
}

int apol_str_is_only_white_space(const char *str)
{
	size_t len, i;
	if (str == NULL)
		return 0;
	len = strlen(str);
	for (i = 0; i < len; i++) {
		if (!isspace(str[i]))
			return 0;
	}
	return 1;
}

int apol_str_strcmp(const void *a, const void *b, void *unused __attribute__ ((unused)))
{
	return strcmp((const char *)a, (const char *)b);
}

void *apol_str_strdup(const void *elem, void *unused __attribute__ ((unused)))
{
	return strdup((const char *)elem);
}
