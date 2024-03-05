/**
 *  @file
 *  Defines the public interface the QPol policy.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Brandon Whalen bwhalen@tresys.com
 *  @author Jeremy Solt jsolt@tresys.com
 *
 *  Copyright (C) 2006-2008 Tresys Technology, LLC
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

#include "qpol_internal.h"
#include <assert.h>
#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <asm/types.h>
#include <unistd.h>

#include <sepol/debug.h>
#include <sepol/handle.h>
#include <sepol/policydb/flask_types.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb.h>
#include <sepol/module.h>
#include <sepol/policydb/module.h>
#include <sepol/policydb/avrule_block.h>

#include <stdbool.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include "expand.h"
#include "queue.h"
#include "iterator_internal.h"

/* redefine input so we can read from a string */
/* borrowed from O'Reilly lex and yacc pg 157 */
char *qpol_src_originalinput;
char *qpol_src_input;
char *qpol_src_inputptr;	       /* current position in qpol_src_input */
char *qpol_src_inputlim;	       /* end of data */

extern void init_scanner(void);
extern int yyparse(void);
extern void init_parser(int, int);
extern queue_t id_queue;
extern unsigned int policydb_errors;
extern unsigned long policydb_lineno;
extern char source_file[];
extern policydb_t *policydbp;
extern int mlspol;

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le16(x) bswap_16(x)
#define le16_to_cpu(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#endif

/* buffer for reading from file */
typedef struct fbuf
{
	char *buf;
	size_t sz;
	int err;
} qpol_fbuf_t;

static void qpol_handle_route_to_callback(void *varg
					  __attribute__ ((unused)), const qpol_policy_t * p, int level, const char *fmt,
					  va_list va_args)
{
	if (!p || !(p->fn)) {
		vfprintf(stderr, fmt, va_args);
		fprintf(stderr, "\n");
		return;
	}

	p->fn(p->varg, p, level, fmt, va_args);
}

static void sepol_handle_route_to_callback(void *varg, sepol_handle_t * sh, const char *fmt, ...)
{
	va_list ap;
	qpol_policy_t *p = varg;

	if (!sh) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		return;
	}

	va_start(ap, fmt);
	qpol_handle_route_to_callback(NULL, p, sepol_msg_get_level(sh), fmt, ap);
	va_end(ap);
}

void qpol_handle_msg(const qpol_policy_t * p, int level, const char *fmt, ...)
{
	va_list ap;

	if (!p) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		return;
	}

	va_start(ap, fmt);
	/* explicit cast here to remove const for sepol handle */
	qpol_handle_route_to_callback((void *)p->varg, p, level, fmt, ap);
	va_end(ap);
}

static void qpol_handle_default_callback(void *varg __attribute__ ((unused)), const qpol_policy_t * p
					 __attribute__ ((unused)), int level, const char *fmt, va_list va_args)
{
	switch (level) {
	case QPOL_MSG_INFO:
	{
		/* by default ignore info messages */
		return;
	}
	case QPOL_MSG_WARN:
	{
		fprintf(stderr, "WARNING: ");
		break;
	}
	case QPOL_MSG_ERR:
	default:
	{
		fprintf(stderr, "ERROR: ");
		break;
	}
	}

	vfprintf(stderr, fmt, va_args);
	fprintf(stderr, "\n");
}

static int read_source_policy(qpol_policy_t * qpolicy, char *progname, int options)
{
	int load_rules = 1;
	if (options & QPOL_POLICY_OPTION_NO_RULES)
		load_rules = 0;
	if ((id_queue = queue_create()) == NULL) {
		ERR(qpolicy, "%s", strerror(ENOMEM));
		return -1;
	}

	policydbp = &qpolicy->p->p;
	mlspol = policydbp->mls;

	INFO(qpolicy, "%s", "Parsing policy. (Step 1 of 5)");
	init_scanner();
	init_parser(1, load_rules);
	errno = 0;
	if (yyparse() || policydb_errors) {
		ERR(qpolicy, "%s:  error(s) encountered while parsing configuration\n", progname);
		queue_destroy(id_queue);
		id_queue = NULL;
//		errno = EIO;
		return -1;
	}
	/* rewind the pointer */
	qpol_src_inputptr = qpol_src_originalinput;
	init_parser(2, load_rules);
	source_file[0] = '\0';
	if (yyparse() || policydb_errors) {
		ERR(qpolicy, "%s:  error(s) encountered while parsing configuration\n", progname);
		queue_destroy(id_queue);
		id_queue = NULL;
//		errno = EIO;
		return -1;
	}
	queue_destroy(id_queue);
	id_queue = NULL;
	if (policydb_errors) {
//		errno = EIO;
		return -1;
	}
	return 0;
}

static int qpol_init_fbuf(qpol_fbuf_t ** fb)
{
	if (fb == NULL)
		return -1;
	*fb = (qpol_fbuf_t *) malloc(sizeof(qpol_fbuf_t));
	if (*fb == NULL)
		return -1;
	(*fb)->buf = NULL;
	(*fb)->sz = 0;
	(*fb)->err = 0;
	return 0;
}

static void qpol_free_fbuf(qpol_fbuf_t ** fb)
{
	if (*fb == NULL)
		return;
	if ((*fb)->sz > 0 && (*fb)->buf != NULL)
		free((*fb)->buf);
	free(*fb);
	return;
}

static void *qpol_read_fbuf(qpol_fbuf_t * fb, size_t bytes, FILE * fp)
{
	size_t sz;

	assert(fb != NULL && fp != NULL);
	assert(!(fb->sz > 0 && fb->buf == NULL));

	if (fb->sz == 0) {
		fb->buf = (char *)malloc(bytes + 1);
		fb->sz = bytes + 1;
	} else if (bytes + 1 > fb->sz) {
		fb->buf = (char *)realloc(fb->buf, bytes + 1);
		fb->sz = bytes + 1;
	}

	if (fb->buf == NULL) {
		fb->err = -1;
		return NULL;
	}

	sz = fread(fb->buf, bytes, 1, fp);
	if (sz != 1) {
		fb->err = -3;
		return NULL;
	}
	fb->err = 0;
	return fb->buf;
}

int qpol_binpol_version(FILE * fp)
{
	__u32 *buf;
	int rt, len;
	qpol_fbuf_t *fb;

	if (fp == NULL)
		return -1;

	if (qpol_init_fbuf(&fb) != 0)
		return -1;

	/* magic # and sz of policy string */
	buf = qpol_read_fbuf(fb, sizeof(__u32) * 2, fp);
	if (buf == NULL) {
		rt = fb->err;
		goto err_return;
	}
	buf[0] = le32_to_cpu(buf[0]);
	if (buf[0] != SELINUX_MAGIC) {
		rt = -2;
		goto err_return;
	}

	len = le32_to_cpu(buf[1]);
	if (len < 0) {
		rt = -3;
		goto err_return;
	}
	/* skip over the policy string */
	if (fseek(fp, sizeof(char) * len, SEEK_CUR) != 0) {
		rt = -3;
		goto err_return;
	}

	/* Read the version, config, and table sizes. */
	buf = qpol_read_fbuf(fb, sizeof(__u32) * 1, fp);
	if (buf == NULL) {
		rt = fb->err;
		goto err_return;
	}
	buf[0] = le32_to_cpu(buf[0]);

	rt = buf[0];
      err_return:
	rewind(fp);
	qpol_free_fbuf(&fb);
	return rt;
}

int qpol_is_file_binpol(FILE * fp)
{
	int rt;
	size_t sz;
	__u32 ubuf;

	sz = fread(&ubuf, sizeof(__u32), 1, fp);
	if (sz != 1)
		rt = 0;

	ubuf = le32_to_cpu(ubuf);
	if (ubuf == SELINUX_MAGIC)
		rt = 1;
	else
		rt = 0;
	rewind(fp);
	return rt;
}

int qpol_is_data_mod_pkg(char * data)
{
	size_t sz;
	__u32 ubuf;

	memcpy(&ubuf, data, sizeof(__u32));

	ubuf = le32_to_cpu(ubuf);
	if (ubuf == SEPOL_MODULE_PACKAGE_MAGIC)
		return 1;

	return 0;
}

int qpol_is_file_mod_pkg(FILE * fp)
{
	size_t sz;
	__u32 ubuf;
	int rt;

	sz = fread(&ubuf, sizeof(__u32), 1, fp);

	if (sz != 1)
		rt = 0;		       /* problem reading file */

	ubuf = le32_to_cpu(ubuf);
	if (ubuf == SEPOL_MODULE_PACKAGE_MAGIC)
		rt = 1;
	else
		rt = 0;
	rewind(fp);
	return rt;
}

static int infer_policy_version(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	const qpol_class_t *obj_class = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_fs_use_t *fsuse = NULL;
	qpol_range_trans_t *rangetrans = NULL;
	uint32_t behavior = 0;
	size_t nvtrans = 0, fsusexattr = 0;
	const char *obj_name = NULL;

	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	if (db->policyvers) {
		/* version already set */
		return STATUS_SUCCESS;
	}

	/* check fs_use for xattr and psid */
	qpol_policy_get_fs_use_iter(policy, &iter);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_iterator_get_item(iter, (void **)&fsuse);
		qpol_fs_use_get_behavior(policy, fsuse, &behavior);
		/* not possible to have xattr and psid in same policy */
		if (behavior == QPOL_FS_USE_XATTR) {
			fsusexattr = 1;
			break;
		} else if (behavior == QPOL_FS_USE_PSID) {
			qpol_iterator_destroy(&iter);
			db->policyvers = 12;
			return STATUS_SUCCESS;
		}
	}
	qpol_iterator_destroy(&iter);

#if defined(HAVE_SEPOL_PERMISSIVE_TYPES) || defined(HAVE_SEPOL_POLICYCAPS)
	ebitmap_node_t *node = NULL;
	unsigned int i = 0;
#endif

	/* 23 : there exists at least one type that is permissive */
#ifdef HAVE_SEPOL_PERMISSIVE_TYPES
	ebitmap_for_each_bit(&db->permissive_map, node, i) {
		if (ebitmap_get_bit(&db->permissive_map, i)) {
			db->policyvers = 23;
			return STATUS_SUCCESS;
		}
	}
#endif

	/* 22 : there exists at least one policy capability */
#ifdef HAVE_SEPOL_POLICYCAPS
	ebitmap_for_each_bit(&db->policycaps, node, i) {
		if (ebitmap_get_bit(&db->policycaps, i)) {
			db->policyvers = 22;
			return STATUS_SUCCESS;
		}
	}
#endif

	/* 21 : object classes other than process for range_transitions */
	qpol_policy_get_range_trans_iter(policy, &iter);
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_iterator_get_item(iter, (void **)&rangetrans);
		qpol_range_trans_get_target_class(policy, rangetrans, &obj_class);
		qpol_class_get_name(policy, obj_class, &obj_name);
		if (strcmp(obj_name, "process")) {
			db->policyvers = 21;
			qpol_iterator_destroy(&iter);
			return STATUS_SUCCESS;
		}
	}
	qpol_iterator_destroy(&iter);

	/* 19 & 20 : mls and validatetrans statements added */
	qpol_policy_get_validatetrans_iter(policy, &iter);
	qpol_iterator_get_size(iter, &nvtrans);
	qpol_iterator_destroy(&iter);
	if (db->mls || nvtrans) {
		db->policyvers = 19;
	}

	/* 18 : the netlink_audit_socket class added */
	else if (hashtab_search(db->p_classes.table, (const hashtab_key_t)"netlink_audit_socket")) {
		db->policyvers = 18;
	}

	/* 17 : IPv6 nodecon statements added */
	else if (db->ocontexts[OCON_NODE6]) {
		db->policyvers = 17;
	}

	/* 16 : conditional policy added */
	else if (db->p_bool_val_to_name && db->p_bool_val_to_name[0]) {
		db->policyvers = 16;

	}
	/* 15 */
	else if (fsusexattr) {
		db->policyvers = 15;
	}

	/* 12 */
	else {
		db->policyvers = 12;
	}

	return STATUS_SUCCESS;
}

/** State tracking struct used in the functions check_disabled, remove_symbol, and prune_disabled_symbols to handle disabled symbols */
struct symbol_pruning_state
{
	qpol_policy_t *p; /**< The policy */
	int symbol_type; /**< The current symbol type being processed */
};

/** Apply callback for hashtab_map_remove_on_error.
 *  This function tests whether a symbol referenced by the policy is declared or only ever required.
 *  Symbols without a declaration are disabled and must be removed.
 *  @param key Symbol key to check.
 *  @param datum Symbol datum to check.
 *  @param args State object (of type struct symbol_pruning_state)
 *  @return 0 if symbol is enabled, 1 if not enabled.
 */
static int check_disabled(hashtab_key_t key, hashtab_datum_t datum, void *args)
{
	struct symbol_pruning_state *s = args;
	if (!is_id_enabled((char *)key, &(s->p->p->p), s->symbol_type))
		return 1;
	return 0;
}

/** Remove callback for hashtab_map_remove_on_error.
 *  Frees all memory associated with a disabled symbol that has been removed from the symbol table.
 *  @param key Symbol key to remove
 *  @param datum Symbol datum to remove
 *  @param args State object (of type struct symbol_pruning_state)
 *  @post All memory associated with the symbol is freed.
 */
static void remove_symbol(hashtab_key_t key, hashtab_datum_t datum, void *args)
{
	struct symbol_pruning_state *s = args;
	switch (s->symbol_type) {
	case SYM_ROLES:
	{
		role_datum_destroy((role_datum_t *) datum);
		break;
	}
	case SYM_TYPES:
	{
		type_datum_destroy((type_datum_t *) datum);
		break;
	}
	case SYM_USERS:
	{
		user_datum_destroy((user_datum_t *) datum);
		break;
	}
	case SYM_BOOLS:
	{
		/* no-op */
		break;
	}
	case SYM_LEVELS:
	{
		level_datum_destroy((level_datum_t *) datum);
		break;
	}
	case SYM_CATS:
	{
		cat_datum_destroy((cat_datum_t *) datum);
		break;
	}
	default:
		return;		       /* invalid type of datum to free; do nothing */
	}
	free(key);
	free(datum);
}

/** Remove symbols that are only required but never declared from the policy.
 *  Removes each disabled symbol freeing all memory associated with it.
 *  @param policy The policy from which disabled symbols should be removed.
 *  @return always 0.
 *  @note Since hashtab_map_remove_on_error does not return any error status,
 *  it is impossible to tell if it has failed; if it fails, the policy will
 *  be in an inconsistent state.
 */
static int prune_disabled_symbols(qpol_policy_t * policy)
{
	if (policy->type == QPOL_POLICY_KERNEL_BINARY)
		return 0;	       /* checkpolicy already prunes disabled symbols */
	struct symbol_pruning_state state;
	state.p = policy;
	for (state.symbol_type = SYM_ROLES; state.symbol_type < SYM_NUM; state.symbol_type++) {
		hashtab_map_remove_on_error(policy->p->p.symtab[state.symbol_type].table, check_disabled, remove_symbol, &state);
	}
	return 0;
}

/** For all symbols that are multiply defined (such as attributes, roles, and users),
 *  union the relevant sets of types and roles from each declaration.
 *  @param policy The policy containig the symbols to union.
 *  @return 0 on success, non-zero on error; if the call fails,
 *  errno will be set, and the policy should be considered invalid.
 */
static int union_multiply_declared_symbols(qpol_policy_t * policy) {
	/* general structure of this function:
	walk role and user symbol tables for each role/user/attribute
		get datum from symtab, get key from array
		look up symbol in scope table
		foreach decl_id in scope entry
			union types/roles bitmap with datum's copy
	*/
	qpol_iterator_t * iter = NULL;
	int error = 0;
	if (qpol_policy_get_type_iter(policy, &iter)) {
		return 1;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		type_datum_t *attr;
		if (qpol_iterator_get_item(iter, (void**)&attr)) {
			error = errno;
			goto err;
		}
		unsigned char isattr = 0;
		if (qpol_type_get_isattr(policy, (qpol_type_t*)attr, &isattr)) {
			error = errno;
			goto err;
		}
		if (!isattr)
			continue;
		const char *name;
		if (qpol_type_get_name(policy, (qpol_type_t*)attr, &name)) {
			error = errno;
			goto err;
		}
		policydb_t *db = &policy->p->p;
		avrule_block_t *blk = db->global;
		for (; blk; blk = blk->next) {
			avrule_decl_t *decl = blk->enabled;
			if (!decl)
				continue; /* disabled */
			type_datum_t *internal_datum = hashtab_search(decl->symtab[SYM_TYPES].table, (const hashtab_key_t)name);
			if (internal_datum == NULL) {
				continue; /* not declared here */
			}
			if (ebitmap_union(&attr->types, &internal_datum->types))
			{
				error = errno;
				ERR(policy, "could not merge declarations for attribute %s", name);
				goto err;
			}
		}
	}
	qpol_iterator_destroy(&iter);

	/* repeat for roles */
	if (qpol_policy_get_role_iter(policy, &iter)) {
		return 1;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		role_datum_t *role;
		if (qpol_iterator_get_item(iter, (void**)&role)) {
			error = errno;
			goto err;
		}
		const char *name;
		if (qpol_role_get_name(policy, (qpol_role_t*)role, &name)) {
			error = errno;
			goto err;
		}
		policydb_t *db = &policy->p->p;
		scope_datum_t* scope_datum = hashtab_search(db->scope[SYM_ROLES].table, (const hashtab_key_t)name);
		if (scope_datum == NULL) {
			ERR(policy, "could not find scope datum for role %s", name);
			error = ENOENT;
			goto err;
		}
		for (uint32_t i = 0; i < scope_datum->decl_ids_len; i++)
		{
			if (db->decl_val_to_struct[scope_datum->decl_ids[i] - 1]->enabled == 0)
				continue; /* block is disabled */
			role_datum_t *internal_datum = hashtab_search(db->decl_val_to_struct[scope_datum->decl_ids[i] - 1]->symtab[SYM_ROLES].table, (const hashtab_key_t)name);
			if (internal_datum == NULL) {
				continue; /* not declared here */
			}
			if (ebitmap_union(&role->types.types, &internal_datum->types.types) || ebitmap_union(&role->dominates, &internal_datum->dominates))
			{
				error = errno;
				ERR(policy, "could not merge declarations for role %s", name);
				goto err;
			}
		}
	}
	qpol_iterator_destroy(&iter);

	/* repeat for users */
	if (qpol_policy_get_user_iter(policy, &iter)) {
		return 1;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		user_datum_t *user;
		if (qpol_iterator_get_item(iter, (void**)&user)) {
			error = errno;
			goto err;
		}
		const char *name;
		if (qpol_user_get_name(policy, (qpol_user_t*)user, &name)) {
			error = errno;
			goto err;
		}
		policydb_t *db = &policy->p->p;
		scope_datum_t* scope_datum = hashtab_search(db->scope[SYM_USERS].table, (const hashtab_key_t)name);
		if (scope_datum == NULL) {
			ERR(policy, "could not find scope datum for user %s", name);
			error = ENOENT;
			goto err;
		}
		for (uint32_t i = 0; i < scope_datum->decl_ids_len; i++)
		{
			if (db->decl_val_to_struct[scope_datum->decl_ids[i] - 1]->enabled == 0)
				continue; /* block is disabled */
			user_datum_t *internal_datum = hashtab_search(db->decl_val_to_struct[scope_datum->decl_ids[i] -1 ]->symtab[SYM_USERS].table, (const hashtab_key_t)name);
			if (internal_datum == NULL) {
				continue; /* not declared here */
			}
			if (ebitmap_union(&user->roles.roles, &internal_datum->roles.roles))
			{
				error = errno;
				ERR(policy, "could not merge declarations for user %s", name);
				goto err;
			}
		}
	}
	qpol_iterator_destroy(&iter);

	return 0;
err:
	qpol_iterator_destroy(&iter);
	errno = error;
	return 1;
}

/* forward declarations see policy_extend.c */
struct qpol_extended_image;
extern void qpol_extended_image_destroy(struct qpol_extended_image **ext);

/**
 * @brief Internal version of qpol_policy_rebuild() version 1.3
 *
 * Implementation of the exported function qpol_policy_rebuild()
 * for version 1.3; this symbol name is not exported.
 * @see qpol_policy_rebuild()
 */
int qpol_policy_rebuild_opt(qpol_policy_t * policy, const int options)
{
	sepol_policydb_t *old_p = NULL;
	sepol_policydb_t **modules = NULL;
	qpol_module_t *base = NULL;
	size_t num_modules = 0, i;
	int error = 0, old_options;

	if (!policy) {
		ERR(NULL, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	/* if kernel binary do nothing */
	if (policy->type == QPOL_POLICY_KERNEL_BINARY)
		return STATUS_SUCCESS;

	/* if options are the same and the modules were not modified, do nothing */
	if (options == policy->options && policy->modified == 0)
		return STATUS_SUCCESS;

	/* cache old policy in case of failure */
	old_p = policy->p;
	policy->p = NULL;
	struct qpol_extended_image *ext = policy->ext;
	policy->ext = NULL;
	old_options = policy->options;
	policy->options = options;

	/* QPOL_POLICY_OPTION_NO_RULES implies QPOL_POLICY_OPTION_NO_NEVERALLOWS */
	if (policy->options & QPOL_POLICY_OPTION_NO_RULES)
		policy->options |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;

	if (policy->type == QPOL_POLICY_MODULE_BINARY) {
		/* allocate enough space for all modules then fill with list of enabled ones only */
		if (!(modules = calloc(policy->num_modules, sizeof(sepol_policydb_t *)))) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
		/* first module is base and cannot be disabled */
		for (i = 1; i < policy->num_modules; i++) {
			if ((policy->modules[i])->enabled) {
				modules[num_modules++] = (policy->modules[i])->p;
			}
		}
		/* have to reopen the base since link alters it */
		if (qpol_module_create_from_file((policy->modules[0])->path, &base)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
		/* take the policy from base and use as new base into which to link */
		policy->p = base->p;
		base->p = NULL;
		qpol_module_destroy(&base);
		if (sepol_link_modules(policy->sh, policy->p, modules, num_modules, 0)) {
			error = EIO;
			goto err;
		}
		free(modules);
	} else {
		/* repeat open process as if qpol_policy_open_from_memory() */
		if (sepol_policydb_create(&(policy->p))) {
			error = errno;
			goto err;
		}

		qpol_src_input = policy->file_data;
		qpol_src_inputptr = qpol_src_input;
		qpol_src_inputlim = qpol_src_inputptr + policy->file_data_sz - 1;
		qpol_src_originalinput = qpol_src_input;

		/* read in source */
		policy->p->p.policy_type = POLICY_BASE;
		if (read_source_policy(policy, "parse", policy->options) < 0) {
			error = errno;
			goto err;
		}

		/* link the source */
		INFO(policy, "%s", "Linking source policy. (Step 2 of 5)");
		if (sepol_link_modules(policy->sh, policy->p, NULL, 0, 0)) {
			error = EIO;
			goto err;
		}
		avtab_destroy(&(policy->p->p.te_avtab));
		avtab_destroy(&(policy->p->p.te_cond_avtab));
		avtab_init(&(policy->p->p.te_avtab));
		avtab_init(&(policy->p->p.te_cond_avtab));
	}

	if (prune_disabled_symbols(policy)) {
		error = errno;
		goto err;
	}

	if (union_multiply_declared_symbols(policy)) {
		error = errno;
		goto err;
	}

	if (qpol_expand_module(policy, !(policy->options & (QPOL_POLICY_OPTION_NO_NEVERALLOWS)))) {
		error = errno;
		goto err;
	}

	if (infer_policy_version(policy)) {
		error = errno;
		goto err;
	}

	if (policy_extend(policy)) {
		error = errno;
		goto err;
	}
	qpol_extended_image_destroy(&ext);

	sepol_policydb_free(old_p);

	return STATUS_SUCCESS;

      err:
	free(modules);

	policy->p = old_p;
	policy->ext = ext;
	policy->options = old_options;
	errno = error;
	return STATUS_ERR;
}

int qpol_policy_rebuild(qpol_policy_t * policy, int options)
{
	return qpol_policy_rebuild_opt(policy, options);
}

/**
 * @brief Internal version of qpol_policy_rebuild() version 1.2 or earlier
 * @deprecated use the 1.3 version.
 * @see qpol_policy_rebuild()
 */
int qpol_policy_rebuild_old(qpol_policy_t * policy)
{
	if (!policy) {
		ERR(NULL, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	/* fail if not a modular policy */
	if (policy->type != QPOL_POLICY_MODULE_BINARY) {
		ERR(policy, "%s", strerror(ENOTSUP));
		errno = ENOTSUP;
		return STATUS_ERR;
	}

	if (!policy->modified)
		return STATUS_SUCCESS;

	return qpol_policy_rebuild_opt(policy, policy->options);
}

/**
 * @brief Internal version of qpol_policy_open_from_file() version 1.3
 *
 * Implementation of the exported function qpol_policy_open_from_file()
 * for version 1.3; this symbol name is not exported.
 * @see qpol_policy_open_from_file()
 */
int qpol_policy_open_from_file_opt(const char *path, qpol_policy_t ** policy, qpol_callback_fn_t fn, void *varg, const int options)
{
	int error = 0, retv = -1;
	FILE *infile = NULL;
	sepol_policy_file_t *pfile = NULL;
	qpol_module_t *mod = NULL;
	int fd = 0;
	struct stat sb;

	if (policy != NULL)
		*policy = NULL;

	if (path == NULL || policy == NULL) {
		/* handle passed as NULL here as it has yet to be created */
		ERR(NULL, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

    errno = 0;
	if (!(*policy = calloc(1, sizeof(qpol_policy_t)))) {
		error = errno;
		ERR(NULL, "%s", strerror(error));
		goto err;
	}
	(*policy)->options = options;

	/* QPOL_POLICY_OPTION_NO_RULES implies QPOL_POLICY_OPTION_NO_NEVERALLOWS */
	if ((*policy)->options & QPOL_POLICY_OPTION_NO_RULES)
		(*policy)->options |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;

	(*policy)->sh = sepol_handle_create();
	if ((*policy)->sh == NULL) {
		error = errno;
		ERR(*policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	if (fn) {
		(*policy)->fn = fn;
		(*policy)->varg = varg;
	} else {
		(*policy)->fn = qpol_handle_default_callback;
	}
	sepol_msg_set_callback((*policy)->sh, sepol_handle_route_to_callback, (*policy));

	if (sepol_policydb_create(&((*policy)->p))) {
		error = errno;
		goto err;
	}

	if (sepol_policy_file_create(&pfile)) {
		error = errno;
		goto err;
	}

	infile = fopen(path, "rb");
	if (infile == NULL) {
		error = errno;
		goto err;
	}

	sepol_policy_file_set_handle(pfile, (*policy)->sh);

    errno=0;
	if (qpol_is_file_binpol(infile)) {
		(*policy)->type = retv = QPOL_POLICY_KERNEL_BINARY;
		sepol_policy_file_set_fp(pfile, infile);
		if (sepol_policydb_read((*policy)->p, pfile)) {
//			error = EIO;
			goto err;
		}
		/* By definition, binary policy cannot have neverallow rules and all other rules are always loaded. */
		(*policy)->options |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;
		(*policy)->options &= ~(QPOL_POLICY_OPTION_NO_RULES);
		if (policy_extend(*policy)) {
			error = errno;
			goto err;
		}
	} else if (qpol_module_create_from_file(path, &mod) == STATUS_SUCCESS) {
		(*policy)->type = retv = QPOL_POLICY_MODULE_BINARY;

		if (qpol_policy_append_module(*policy, mod)) {
			error = errno;
			goto err;
		}
		/* *policy now owns mod */
		mod = NULL;
		if (qpol_policy_rebuild_opt(*policy, options)) {
			error = errno;
			goto err;
		}
	} else {
		(*policy)->type = retv = QPOL_POLICY_KERNEL_SOURCE;
		fd = fileno(infile);
		if (fd < 0) {
			error = errno;
			goto err;
		}
		if (fstat(fd, &sb) < 0) {
			error = errno;
			ERR(*policy, "Can't stat '%s':	%s\n", path, strerror(errno));
			goto err;
		}
		qpol_src_input = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (qpol_src_input == MAP_FAILED) {
			error = errno;
			ERR(*policy, "Can't map '%s':  %s\n", path, strerror(errno));

			goto err;
		}
		qpol_src_inputptr = qpol_src_input;
		qpol_src_inputlim = &qpol_src_inputptr[sb.st_size - 1];
		qpol_src_originalinput = qpol_src_input;

		/* store mmaped version for rebuild() */
		(*policy)->file_data = qpol_src_originalinput;
		(*policy)->file_data_sz = sb.st_size;
		(*policy)->file_data_type = QPOL_POLICY_FILE_DATA_TYPE_MMAP;

		(*policy)->p->p.policy_type = POLICY_BASE;
		if (read_source_policy(*policy, "libqpol", (*policy)->options) < 0) {
			error = errno;
			goto err;
		}

		/* link the source */
		INFO(*policy, "%s", "Linking source policy. (Step 2 of 5)");
		if (sepol_link_modules((*policy)->sh, (*policy)->p, NULL, 0, 0)) {
			error = EIO;
			goto err;
		}
		avtab_destroy(&((*policy)->p->p.te_avtab));
		avtab_destroy(&((*policy)->p->p.te_cond_avtab));
		avtab_init(&((*policy)->p->p.te_avtab));
		avtab_init(&((*policy)->p->p.te_cond_avtab));

		if (prune_disabled_symbols(*policy)) {
			error = errno;
			goto err;
		}

		if (union_multiply_declared_symbols(*policy)) {
			error = errno;
			goto err;
		}

		/* expand */
		if (qpol_expand_module(*policy, !(options & (QPOL_POLICY_OPTION_NO_NEVERALLOWS)))) {
			error = errno;
			goto err;
		}

		if (infer_policy_version(*policy)) {
			error = errno;
			goto err;
		}
		if (policy_extend(*policy)) {
			error = errno;
			goto err;
		}
	}

	fclose(infile);
	sepol_policy_file_free(pfile);
	return retv;

      err:
	qpol_policy_destroy(policy);
	qpol_module_destroy(&mod);
	sepol_policy_file_free(pfile);
	if (infile)
		fclose(infile);
	errno = error;
	return -1;
}

int qpol_policy_open_from_file(const char *path, qpol_policy_t ** policy, qpol_callback_fn_t fn, void *varg, const int options)
{
	return qpol_policy_open_from_file_opt(path, policy, fn, varg, options);
}

int qpol_policy_open_from_file_no_rules(const char *path, qpol_policy_t ** policy, qpol_callback_fn_t fn, void *varg)
{
	return qpol_policy_open_from_file_opt(path, policy, fn, varg, QPOL_POLICY_OPTION_NO_RULES);
}

/**
 * @brief Internal version of qpol_policy_open_from_memory() version 1.3
 *
 * Implementation of the exported function qpol_policy_open_from_memory()
 * for version 1.3; this symbol name is not exported.
 * @see qpol_policy_open_from_memory()
 */
int qpol_policy_open_from_memory_opt(qpol_policy_t ** policy, const char *filedata, size_t size, qpol_callback_fn_t fn, void *varg,
				     const int options)
{
	int error = 0;
	if (policy == NULL || filedata == NULL)
		return -1;
	*policy = NULL;

	if (!(*policy = calloc(1, sizeof(qpol_policy_t)))) {
		error = errno;
		goto err;
	}
	(*policy)->options = options;

	/* QPOL_POLICY_OPTION_NO_RULES implies QPOL_POLICY_OPTION_NO_NEVERALLOWS */
	if ((*policy)->options & QPOL_POLICY_OPTION_NO_RULES)
		(*policy)->options |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;

	(*policy)->sh = sepol_handle_create();
	if ((*policy)->sh == NULL) {
		error = errno;
		ERR(*policy, "%s", strerror(error));
		errno = error;
		return -1;
	}

	sepol_msg_set_callback((*policy)->sh, sepol_handle_route_to_callback, (*policy));
	if (fn) {
		(*policy)->fn = fn;
		(*policy)->varg = varg;
	} else {
		(*policy)->fn = qpol_handle_default_callback;
	}

	if (sepol_policydb_create(&((*policy)->p))) {
		error = errno;
		goto err;
	}

	qpol_src_input = (char *)filedata;
	qpol_src_inputptr = qpol_src_input;
	qpol_src_inputlim = qpol_src_inputptr + size - 1;
	qpol_src_originalinput = qpol_src_input;

	/* store filedata for rebuild() */
	if (!((*policy)->file_data = malloc(size))) {
		error = errno;
		goto err;
	}
	memcpy((*policy)->file_data, filedata, size);
	(*policy)->file_data_sz = size;
	(*policy)->file_data_type = QPOL_POLICY_FILE_DATA_TYPE_MEM;

	/* read in source */
	(*policy)->p->p.policy_type = POLICY_BASE;
	if (read_source_policy(*policy, "parse", (*policy)->options) < 0)
		exit(1);

	/* link the source */
	INFO(*policy, "%s", "Linking source policy. (Step 2 of 5)");
	if (sepol_link_modules((*policy)->sh, (*policy)->p, NULL, 0, 0)) {
		error = EIO;
		goto err;
	}
	avtab_destroy(&((*policy)->p->p.te_avtab));
	avtab_destroy(&((*policy)->p->p.te_cond_avtab));
	avtab_init(&((*policy)->p->p.te_avtab));
	avtab_init(&((*policy)->p->p.te_cond_avtab));

	if (prune_disabled_symbols(*policy)) {
		error = errno;
		goto err;
	}

	if (union_multiply_declared_symbols(*policy)) {
		error = errno;
		goto err;
	}

	/* expand */
	if (qpol_expand_module(*policy, !(options & (QPOL_POLICY_OPTION_NO_NEVERALLOWS)))) {
		error = errno;
		goto err;
	}

	return 0;
      err:
	qpol_policy_destroy(policy);
	errno = error;
	return -1;

}

#if LINK_SHARED == 0
int qpol_policy_open_from_memory(qpol_policy_t ** policy, const char *filedata, size_t size, qpol_callback_fn_t fn, void *varg,
				 const int options)
{
	return qpol_policy_open_from_memory_opt(policy, filedata, size, fn, varg, options);
}
#endif

/**
 * @brief Internal version of qpol_policy_open_from_file() version 1.2 or earlier
 * @deprecated use the 1.3 version.
 * @see qpol_policy_open_from_file()
 */
int qpol_policy_open_from_file_old(const char *path, qpol_policy_t ** policy, qpol_callback_fn_t fn, void *varg)
{
	return qpol_policy_open_from_file(path, policy, fn, varg, 0);
}

/**
 * @brief Internal version of qpol_policy_open_from_memory() version 1.2 or earlier
 * @deprecated use the 1.3 version.
 * @see qpol_policy_open_from_memory()
 */
int qpol_policy_open_from_memory_old(qpol_policy_t ** policy, const char *filedata, size_t size, qpol_callback_fn_t fn, void *varg)
{
	return qpol_policy_open_from_memory_opt(policy, filedata, size, fn, varg, 0);
}

void qpol_policy_destroy(qpol_policy_t ** policy)
{
	if (policy != NULL && *policy != NULL) {
		sepol_policydb_free((*policy)->p);
		sepol_handle_destroy((*policy)->sh);
		qpol_extended_image_destroy(&((*policy)->ext));
		if ((*policy)->modules) {
			size_t i = 0;
			for (i = 0; i < (*policy)->num_modules; i++) {
				qpol_module_destroy(&((*policy)->modules[i]));
			}
			free((*policy)->modules);
		}
		if ((*policy)->file_data_type == QPOL_POLICY_FILE_DATA_TYPE_MEM) {
			free((*policy)->file_data);
		} else if ((*policy)->file_data_type == QPOL_POLICY_FILE_DATA_TYPE_MMAP) {
			munmap((*policy)->file_data, (*policy)->file_data_sz);
		}
		free(*policy);
		*policy = NULL;
	}
}

int qpol_policy_reevaluate_conds(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	cond_node_t *cond = NULL;
	cond_av_list_t *list_ptr = NULL;

	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	for (cond = db->cond_list; cond; cond = cond->next) {
		/* evaluate cond */
		cond->cur_state = cond_evaluate_expr(db, cond->expr);
		if (cond->cur_state < 0) {
			ERR(policy, "Error evaluating conditional: %s", strerror(EILSEQ));
			errno = EILSEQ;
			return STATUS_ERR;
		}

		/* walk true list */
		for (list_ptr = cond->true_list; list_ptr; list_ptr = list_ptr->next) {
			/* field not used (except by write),
			 * now storing list and enabled flags */
			if (cond->cur_state)
				list_ptr->node->merged |= QPOL_COND_RULE_ENABLED;
			else
				list_ptr->node->merged &= ~(QPOL_COND_RULE_ENABLED);
		}

		/* walk false list */
		for (list_ptr = cond->false_list; list_ptr; list_ptr = list_ptr->next) {
			/* field not used (except by write),
			 * now storing list and enabled flags */
			if (!cond->cur_state)
				list_ptr->node->merged |= QPOL_COND_RULE_ENABLED;
			else
				list_ptr->node->merged &= ~(QPOL_COND_RULE_ENABLED);
		}
	}

	return STATUS_SUCCESS;
}

int qpol_policy_append_module(qpol_policy_t * policy, qpol_module_t * module)
{
	qpol_module_t **tmp = NULL;
	int error = 0;

	if (!policy || !module) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!(tmp = realloc(policy->modules, (1 + policy->num_modules) * sizeof(qpol_module_t *)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}

	policy->modules = tmp;
	policy->modules[policy->num_modules] = module;
	policy->num_modules++;
	policy->modified = 1;
	module->parent = policy;

	return STATUS_SUCCESS;
}

typedef struct mod_state
{
	qpol_module_t **list;
	size_t cur;
	size_t end;
} mod_state_t;

static int mod_state_end(const qpol_iterator_t * iter)
{
	mod_state_t *ms;

	if (!iter || !(ms = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 1;
	}

	return (ms->cur >= ms->end);
}

static void *mod_state_get_cur(const qpol_iterator_t * iter)
{
	mod_state_t *ms;

	if (!iter || !(ms = qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return ms->list[ms->cur];
}

static int mod_state_next(qpol_iterator_t * iter)
{
	mod_state_t *ms;

	if (!iter || !(ms = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	ms->cur++;

	return STATUS_SUCCESS;
}

static size_t mod_state_size(const qpol_iterator_t * iter)
{
	mod_state_t *ms;

	if (!iter || !(ms = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	return ms->end;
}

int qpol_policy_get_module_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	mod_state_t *ms = NULL;
	int error = 0;

	if (!policy || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (!(ms = calloc(1, sizeof(mod_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}

	if (qpol_iterator_create(policy, (void *)ms, mod_state_get_cur, mod_state_next, mod_state_end, mod_state_size, free, iter)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		free(ms);
		errno = error;
		return STATUS_ERR;
	}

	ms->end = policy->num_modules;
	ms->list = policy->modules;

	return STATUS_SUCCESS;
}

static int is_mls_policy(const qpol_policy_t * policy)
{
	policydb_t *db = NULL;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	if (db->mls != 0)
		return 1;
	else
		return 0;
}

int qpol_policy_is_mls_enabled(qpol_policy_t * policy)
{
	return is_mls_policy(policy);
}

int qpol_policy_get_policy_version(const qpol_policy_t * policy, unsigned int *version)
{
	policydb_t *db;

	if (version != NULL)
		*version = 0;

	if (policy == NULL || version == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	*version = db->policyvers;

	return STATUS_SUCCESS;
}

int qpol_policy_get_type(const qpol_policy_t * policy, int *type)
{
	if (!policy || !type) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*type = policy->type;

	return STATUS_SUCCESS;
}

int qpol_policy_has_capability(const qpol_policy_t * policy, qpol_capability_e cap)
{
	unsigned int version = 0;

	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return 0;
	}

	qpol_policy_get_policy_version(policy, &version);

	switch (cap) {
	case QPOL_CAP_ATTRIB_NAMES:
	{
		if ((policy->type == QPOL_POLICY_KERNEL_SOURCE || policy->type == QPOL_POLICY_MODULE_BINARY) || (version >= 24))
			return 1;
		break;
	}
	case QPOL_CAP_SYN_RULES:
	{
		if (policy->type == QPOL_POLICY_KERNEL_SOURCE || policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_LINE_NUMBERS:
	{
		if (policy->type == QPOL_POLICY_KERNEL_SOURCE)
			return 1;
		break;
	}
	case QPOL_CAP_CONDITIONALS:
	{
		if (version >= 16 || policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_MLS:
	{
		return is_mls_policy(policy);
	}
	case QPOL_CAP_MODULES:
	{
		if (policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_POLCAPS:
	{
		if (version >= 22 && policy->type != QPOL_POLICY_MODULE_BINARY)
			return 1;
		if (version >= 7 && policy->type == QPOL_POLICY_MODULE_BINARY)
			return 1;
		break;
	}
	case QPOL_CAP_RULES_LOADED:
	{
		if (!(policy->options & QPOL_POLICY_OPTION_NO_RULES))
			return 1;
		break;
	}
	case QPOL_CAP_SOURCE:
	{
		if (policy->type == QPOL_POLICY_KERNEL_SOURCE)
			return 1;
		break;
	}
	case QPOL_CAP_NEVERALLOW:
	{
		if (!(policy->options & QPOL_POLICY_OPTION_NO_NEVERALLOWS) && policy->type != QPOL_POLICY_KERNEL_BINARY)
			return 1;
		break;
	}
	default:
	{
		ERR(policy, "%s", "Unknown capability");
		errno = EDOM;
		break;
	}
	}
	return 0;
}
