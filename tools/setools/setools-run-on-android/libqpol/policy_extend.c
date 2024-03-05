/**
 *  @file
 *  Implementation of the interface for loading and using an extended
 *  policy image.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
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

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/flask.h>
#include <sepol/policydb/ebitmap.h>
#include <sepol/policydb/expand.h>
#ifdef HAVE_SEPOL_ERRCODES
#include <sepol/errcodes.h>
#endif
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include <qpol/iterator.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "qpol_internal.h"
#include "iterator_internal.h"
#include "syn_rule_internal.h"

#ifdef SETOOLS_DEBUG
#include <math.h>
#endif

#define OBJECT_R "object_r"

#define QPOL_SYN_RULE_TABLE_BITS 16
#define QPOL_SYN_RULE_TABLE_SIZE (1 << QPOL_SYN_RULE_TABLE_BITS)
#define QPOL_SYN_RULE_TABLE_MASK (QPOL_SYN_RULE_TABLE_SIZE - 1)

/* original hashing function below */
/*
#define QPOL_SYN_RULE_TABLE_HASH(rule_key) \
((rule_key->class_val + \
 (rule_key->target_val << 2) +\
 (rule_key->source_val << 9)) & \
 QPOL_SYN_RULE_TABLE_MASK)
*/

/* new hashing function, introduced in SETools 3.3 */
#define QPOL_SYN_RULE_TABLE_HASH(rule_key) \
(((((rule_key->source_val & 0xff) << 8) | (rule_key->target_val & 0xff)) ^ \
 (rule_key->class_val & 0xf) ^ \
 ((int) ((size_t) rule_key->cond) & 0xfff0)) & QPOL_SYN_RULE_TABLE_MASK)

typedef struct qpol_syn_rule_key
{
	uint32_t rule_type;
	uint32_t source_val;
	uint32_t target_val;
	uint32_t class_val;
	cond_node_t *cond;
} qpol_syn_rule_key_t;

typedef struct qpol_syn_rule_list
{
	struct qpol_syn_rule *rule;
	struct qpol_syn_rule_list *next;
} qpol_syn_rule_list_t;

typedef struct qpol_syn_rule_node
{
	qpol_syn_rule_key_t key;
	qpol_syn_rule_list_t *rules;
	struct qpol_syn_rule_node *next;
} qpol_syn_rule_node_t;

typedef struct qpol_syn_rule_table
{
	qpol_syn_rule_node_t **buckets;
} qpol_syn_rule_table_t;

typedef struct qpol_extended_image
{
	qpol_syn_rule_table_t *syn_rule_table;
	struct qpol_syn_rule **syn_rule_master_list;
	size_t master_list_sz;
} qpol_extended_image_t;

struct extend_bogus_alias_struct
{
	qpol_policy_t *q;
	int num_bogus_aliases;
};

static int extend_find_bogus_alias(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *args)
{
	struct extend_bogus_alias_struct *e = (struct extend_bogus_alias_struct *)args;
	/* within libqpol, qpol_type_t is the same a libsepol's type_datum_t */
	qpol_type_t *qtype = (qpol_type_t *) datum;
	type_datum_t *type = (type_datum_t *) datum;
	unsigned char isalias;
	qpol_type_get_isalias(e->q, qtype, &isalias);
	return isalias && type->s.value == 0;
}

static void extend_remove_bogus_alias(hashtab_key_t key, hashtab_datum_t datum, void *args)
{
	struct extend_bogus_alias_struct *e = (struct extend_bogus_alias_struct *)args;
	free(key);
	type_datum_t *type = (type_datum_t *) datum;
	type_datum_destroy(type);
	free(type);
	e->num_bogus_aliases++;
}

/**
 *  Search the policy for aliases that have a value of 0.  These come
 *  from modular policies with disabled aliases, but end up being
 *  written to the policy anyways due to a bug in libsepol.  These
 *  bogus aliases are removed from the policy.
 *  @param policy Policy that may contain broken aliases.  This policy
 *  will be altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails, errno
 *  will be set.  On failure, the policy state may be inconsistent.
 */
static int qpol_policy_remove_bogus_aliases(qpol_policy_t * policy)
{
	policydb_t *db = NULL;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	struct extend_bogus_alias_struct e = { policy, 0 };
	hashtab_map_remove_on_error(db->p_types.table, extend_find_bogus_alias, extend_remove_bogus_alias, &e);

#ifdef SETOOLS_DEBUG
	if (e.num_bogus_aliases > 0) {
		WARN(policy, "%s", "This policy contained disabled aliases; they have been removed.");
	}
#endif

	return 0;
}

/**
 *  Builds data for the attributes and inserts them into the policydb.
 *  This function modifies the policydb. Names created for attributes
 *  are of the form @ttr<value> where value is the value of the attribute
 *  as a four digit number (prepended with 0's as needed).
 *  @param policy The policy from which to read the attribute map and
 *  create the type data for the attributes. This policy will be altered
 *  by this function.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent
 *  especially in the case where the hashtab functions return the error.
 */
static int qpol_policy_build_attrs_from_map(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	size_t i;
	uint32_t bit = 0, count = 0;
	ebitmap_node_t *node = NULL;
	type_datum_t *tmp_type = NULL, *orig_type;
	char *tmp_name = NULL, buff[10];
	int error = 0, retv;

	INFO(policy, "%s", "Generating attributes for policy. (Step 4 of 5)");
	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	db = &policy->p->p;

	memset(&buff, 0, 10 * sizeof(char));

	for (i = 0; i < db->p_types.nprim; i++) {
		count = 0;
		ebitmap_for_each_bit(&db->attr_type_map[i], node, bit) {
			if (ebitmap_node_get_bit(node, bit))
				count++;
		}
		if (count == 0) {
			continue;
		}
		/* first create a new type_datum_t for the attribute,
		 * with the attribute's type_list consisting of types
		 * with this attribute */
		/* Does not exist */
		if (db->p_type_val_to_name[i] == NULL){
			snprintf(buff, 9, "@ttr%04zd", i + 1);
			tmp_name = strdup(buff);
			if (!tmp_name) {
				error = errno;
				goto err;
			}
		}

		/* Already exists */
		else 
			tmp_name = db->p_type_val_to_name[i];

		tmp_type = calloc(1, sizeof(type_datum_t));
		if (!tmp_type) {
			error = errno;
			goto err;
		}
		tmp_type->primary = 1;
		tmp_type->flavor = TYPE_ATTRIB;
		tmp_type->s.value = i + 1;
		if (ebitmap_cpy(&tmp_type->types, &db->attr_type_map[i])) {
			error = ENOMEM;
			goto err;
		}

		/* now go through each of the member types, and set
		 * their type_list bit to point back */
		ebitmap_for_each_bit(&tmp_type->types, node, bit) {
			if (ebitmap_node_get_bit(node, bit)) {
				orig_type = db->type_val_to_struct[bit];
				if (ebitmap_set_bit(&orig_type->types, tmp_type->s.value - 1, 1)) {
					error = ENOMEM;
					goto err;
				}
			}
		}
		/* Does not exist - insert new */
		if (db->p_type_val_to_name[i] == NULL){
			retv = hashtab_insert(db->p_types.table, (hashtab_key_t) tmp_name, (hashtab_datum_t) tmp_type);
			if (retv) {
				if (retv == SEPOL_ENOMEM)
					error = db->p_types.table ? ENOMEM : EINVAL;
				else
					error = EEXIST;
				goto err;
			}
		}
		/* Already exists - replace old */
		else {
			retv = hashtab_replace(db->p_types.table, (hashtab_key_t) tmp_name, (hashtab_datum_t) tmp_type, NULL, NULL);
			if (retv) {
				if (retv == SEPOL_ENOMEM)
					error = db->p_types.table ? ENOMEM : EINVAL;
				else
					error = EEXIST;
				goto err;
			}
		}

		db->p_type_val_to_name[i] = tmp_name;
		db->type_val_to_struct[i] = tmp_type;

		/* memory now owned by symtab do not free */
		tmp_name = NULL;
		tmp_type = NULL;
	}

	return STATUS_SUCCESS;

      err:
	free(tmp_name);
	type_datum_destroy(tmp_type);
	free(tmp_type);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return STATUS_ERR;
}

/**
 *  Builds data for empty attributes and inserts them into the policydb.
 *  This function modifies the policydb. Names created for the attributes
 *  are of the form @ttr<value> where value is the value of the attribute
 *  as a four digit number (prepended with 0's as needed).
 *  @param policy The policy to which to add type data for attributes.
 *  This policy will be altered by this function.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent
 *  especially in the case where the hashtab functions return the error.
 */
static int qpol_policy_fill_attr_holes(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	char *tmp_name = NULL, buff[10];
	int error = 0, retv = 0;
	ebitmap_t tmp_bmap = { NULL, 0 };
	type_datum_t *tmp_type = NULL;
	size_t i;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	memset(&buff, 0, 10 * sizeof(char));

	for (i = 0; i < db->p_types.nprim; i++) {
		if (db->type_val_to_struct[i])
			continue;
		snprintf(buff, 9, "@ttr%04zd", i + 1);
		tmp_name = strdup(buff);
		if (!tmp_name) {
			error = errno;
			goto err;
		}
		tmp_type = calloc(1, sizeof(type_datum_t));
		if (!tmp_type) {
			error = errno;
			goto err;
		}
		tmp_type->primary = 1;
		tmp_type->flavor = TYPE_ATTRIB;
		tmp_type->s.value = i + 1;
		tmp_type->types = tmp_bmap;

		retv = hashtab_insert(db->p_types.table, (hashtab_key_t) tmp_name, (hashtab_datum_t) tmp_type);
		if (retv) {
			if (retv == SEPOL_ENOMEM)
				error = db->p_types.table ? ENOMEM : EINVAL;
			else
				error = EEXIST;
			goto err;
		}
		db->p_type_val_to_name[i] = tmp_name;
		db->type_val_to_struct[i] = tmp_type;

		/* memory now owned by symtab do not free */
		tmp_name = NULL;
		tmp_type = NULL;
	}

	return STATUS_SUCCESS;

      err:
	free(tmp_type);
	free(tmp_name);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return STATUS_ERR;
}

static char *sidnames[] = {
	"undefined",
	"kernel",
	"security",
	"unlabeled",
	"fs",
	"file",
	"file_labels",
	"init",
	"any_socket",
	"port",
	"netif",
	"netmsg",
	"node",
	"igmp_packet",
	"icmp_socket",
	"tcp_socket",
	"sysctl_modprobe",
	"sysctl",
	"sysctl_fs",
	"sysctl_kernel",
	"sysctl_net",
	"sysctl_net_unix",
	"sysctl_vm",
	"sysctl_dev",
	"kmod",
	"policy",
	"scmp_packet",
	"devnull"
};

/**
 *  Uses names from flask to fill in the isid names which are not normally
 *  saved. This function modified the policydb.
 *  @param policy Policy to which to add sid names.
 *  This policy will be altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent.
 */
static int qpol_policy_add_isid_names(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	ocontext_t *sid = NULL;
	uint32_t val = 0;
	int error = 0;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	for (sid = db->ocontexts[OCON_ISID]; sid; sid = sid->next) {
		val = (uint32_t) sid->sid[0];
		if (val > SECINITSID_NUM)
			val = 0;

		if (!sid->u.name) {
			sid->u.name = strdup(sidnames[val]);
			if (!sid->u.name) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				errno = error;
				return STATUS_ERR;
			}
		}
	}

	return 0;
}

static int extend_assign_role_to_user(hashtab_key_t k __attribute__ ((unused)), hashtab_datum_t d, void *args)
{
	user_datum_t *user = (user_datum_t *) d;
	uint32_t *value = (uint32_t *) args;
	if (ebitmap_set_bit(&user->roles.roles, *value - 1, 1)) {
		return -1;
	}
	return 0;
}

/**
 *  Modify the special role 'object_r' by assigning it to all users,
 *  and all types to object_r.  This function modifies the policydb.
 *  @param policy Policy containing object_r.  This policy will be
 *  altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails, errno
 *  will be set.  On failure, the policy state may be inconsistent.
 */
static int qpol_policy_add_object_r(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	int error = 0;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	hashtab_datum_t datum = hashtab_search(db->p_roles.table, (const hashtab_key_t)OBJECT_R);
	if (datum == NULL) {
		ERR(policy, "%s", OBJECT_R " not found in policy!");
		errno = EIO;
		assert(0);
		return STATUS_ERR;
	}

	role_datum_t *role = (role_datum_t *) datum;

	uint32_t value = role->s.value;

	if (hashtab_map(db->p_users.table, extend_assign_role_to_user, &value) < 0) {
		return STATUS_ERR;
	}

	qpol_iterator_t *iter;
	if (qpol_policy_get_type_iter(policy, &iter) < 0) {
		return STATUS_ERR;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		const qpol_type_t *type;
		unsigned char isattr, isalias;
		if (qpol_iterator_get_item(iter, (void **)&type) < 0 ||
		    qpol_type_get_isattr(policy, type, &isattr) < 0 || qpol_type_get_isalias(policy, type, &isalias) < 0) {
			error = errno;
			qpol_iterator_destroy(&iter);
			errno = error;
			return STATUS_ERR;
		}
		if (isattr || isalias) {
			continue;
		}
		if (qpol_type_get_value(policy, type, &value) < 0) {
			error = errno;
			qpol_iterator_destroy(&iter);
			errno = error;
			return STATUS_ERR;
		}
		if (ebitmap_set_bit(&role->types.types, value - 1, 1)) {
			error = errno;
			qpol_iterator_destroy(&iter);
			errno = error;
			return STATUS_ERR;
		}
	}
	qpol_iterator_destroy(&iter);

	return 0;
}

/**
 *  If the given policy's version is higher than the running system's
 *  version, then mark it as different.  In a future version of
 *  libqpol, accessors will return data as if the policy were really
 *  the new version rather than what it actually is.
 */
static int qpol_policy_match_system(qpol_policy_t * policy)
{
	/* Make work on systems without libselinux */
	return 0;
}

/**
 *  Walks the conditional list and adds links for reverse look up from
 *  a te/av rule to the conditional from which it came.
 *  @param policy The policy to which to add conditional trace backs.
 *  This policy will be altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent.
 */
static int qpol_policy_add_cond_rule_traceback(qpol_policy_t * policy)
{
	policydb_t *db = NULL;
	cond_node_t *cond = NULL;
	cond_av_list_t *list_ptr = NULL;
	qpol_iterator_t *iter = NULL;
	avtab_ptr_t rule = NULL;
	int error = 0;
	uint32_t rules = 0;

	INFO(policy, "%s", "Building conditional rules tables. (Step 5 of 5)");
	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	rules = (QPOL_RULE_ALLOW | QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT);
	if (!(policy->options & QPOL_POLICY_OPTION_NO_NEVERALLOWS))
		rules |= QPOL_RULE_NEVERALLOW;

	/* mark all unconditional rules as enabled */
	if (qpol_policy_get_avrule_iter(policy, rules, &iter))
		return STATUS_ERR;
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&rule)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			errno = error;
			return STATUS_ERR;
		}
		rule->parse_context = NULL;
		rule->merged = QPOL_COND_RULE_ENABLED;
	}
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_terule_iter(policy, (QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER), &iter))
		return STATUS_ERR;
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&rule)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			errno = error;
			return STATUS_ERR;
		}
		rule->parse_context = NULL;
		rule->merged = QPOL_COND_RULE_ENABLED;
	}
	qpol_iterator_destroy(&iter);

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
			/* field not used after parse, now stores cond */
			list_ptr->node->parse_context = (void *)cond;
			/* field not used (except by write),
			 * now storing list and enabled flags */
			list_ptr->node->merged = QPOL_COND_RULE_LIST;
			if (cond->cur_state)
				list_ptr->node->merged |= QPOL_COND_RULE_ENABLED;
		}

		/* walk false list */
		for (list_ptr = cond->false_list; list_ptr; list_ptr = list_ptr->next) {
			/* field not used after parse, now stores cond */
			list_ptr->node->parse_context = (void *)cond;
			/* field not used (except by write),
			 * now storing list and enabled flags */
			list_ptr->node->merged = 0;	/* i.e. !QPOL_COND_RULE_LIST */
			if (!cond->cur_state)
				list_ptr->node->merged |= QPOL_COND_RULE_ENABLED;
		}
	}

	return 0;
}

/**
 *  Free all allocated memory used by a qpol_syn_rule.
 *  @param r Reference pointer to the rule to destroy.
 */
static void qpol_syn_rule_destroy(struct qpol_syn_rule **r)
{
	if (!r || !(*r))
		return;

	free(*r);
	*r = NULL;
}

/**
 *  Free all memory used by a syn rule list.
 *  @param list Reference pointer to the head node of
 *  the syn rule list to destroy. All nodes in the list will
 *  be destroyed.
 */
static void qpol_syn_rule_list_destroy(qpol_syn_rule_list_t ** list)
{
	qpol_syn_rule_list_t *cur = NULL, *next = NULL;

	if (!list || !(*list))
		return;

	for (cur = *list; cur; cur = next) {
		next = cur->next;
		free(cur);
	}
}

/**
 *  Free all memory used by a syn rule node in the rule table.
 *  @param node Reference pointer to the first node in the chain.
 *  All nodes in the chain will be destroyed.
 */
static void qpol_syn_rule_node_destroy(qpol_syn_rule_node_t ** node)
{
	qpol_syn_rule_node_t *cur = NULL, *next = NULL;

	if (!node || !(*node))
		return;

	for (cur = *node; cur; cur = next) {
		next = cur->next;
		qpol_syn_rule_list_destroy(&cur->rules);
		free(cur);
	}
}

/**
 *  Free all memory used by the syntactic rule table.
 * @param t Reference pointer to the table to destroy.
 */
static void qpol_syn_rule_table_destroy(qpol_syn_rule_table_t ** t)
{
	size_t i = 0;

	if (!t || !(*t))
		return;

	for (i = 0; i < QPOL_SYN_RULE_TABLE_SIZE; i++)
		qpol_syn_rule_node_destroy(&((*t)->buckets[i]));

	free((*t)->buckets);
	free(*t);
	*t = NULL;
}

/**
 *  Find the node in the syntactic rule hash table corresponding to a key.
 *  @param table The table to search.
 *  @param key The key for which to search.
 *  @return a valid qpol_syn_rule_node_t pointer on success or NULL on failure.
 */
static qpol_syn_rule_node_t *qpol_syn_rule_table_find_node_by_key(const qpol_syn_rule_table_t * table,
								  const qpol_syn_rule_key_t * key)
{
	qpol_syn_rule_node_t *node = NULL;

	for (node = table->buckets[QPOL_SYN_RULE_TABLE_HASH(key)]; node; node = node->next) {
		if ((node->key.rule_type & key->rule_type) &&
		    (node->key.source_val == key->source_val) &&
		    (node->key.target_val == key->target_val) &&
		    (node->key.class_val == key->class_val) && (node->key.cond == key->cond))
			return node;
	}

	return NULL;
}

/**
 *  Given a syn rule key and a syn rule, adds the key/rule pair to the
 *  syn rule table.  Note that this function takes ownership of the
 *  key.
 *
 *  @param policy Policy associated with the rule.
 *  @param table The table to which to add the rule.
 *  @param key Hashtable key for rule lookup.
 *  @param rule The rule to add.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and the table may be in an inconsistent state.
 */
static int qpol_syn_rule_table_insert_entry(qpol_policy_t * policy,
					    qpol_syn_rule_table_t * table, qpol_syn_rule_key_t * key, struct qpol_syn_rule *rule)
{
	int error = 0;
	qpol_syn_rule_node_t *table_node = NULL;
	qpol_syn_rule_list_t *list_entry = NULL;

	if (!(list_entry = malloc(sizeof(qpol_syn_rule_list_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		return -1;
	}
	list_entry->rule = rule;

	table_node = qpol_syn_rule_table_find_node_by_key(table, key);
	if (table_node) {
		list_entry->next = table_node->rules;
		table_node->rules = list_entry;
	} else {
		list_entry->next = NULL;
		if (!(table_node = malloc(sizeof(qpol_syn_rule_node_t)))) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			free(list_entry);
			return -1;
		}
		table_node->key = *key;
		table_node->rules = list_entry;
		size_t hash = QPOL_SYN_RULE_TABLE_HASH(key);
		table_node->next = table->buckets[hash];
		table->buckets[hash] = table_node;
	}
	return 0;
}

/**
 *  Add a syntactic rule (sepol's avrule_t) to the syntactic rule table.
 *  @param policy Policy associated with the rule.
 *  @param table The table to which to add the rule.
 *  @param rule The rule to add.
 *  @param cond The conditional associated with the rule (NULL if
 *  unconditional).  with the rule (needed for conditional tracking).
 *  @param branch If the rule is conditional, then 0 if in the true
 *  branch, 1 if in else.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and the table may be in an inconsistent state.
 */
static int qpol_syn_rule_table_insert_sepol_avrule(qpol_policy_t * policy, qpol_syn_rule_table_t * table, avrule_t * rule,
						   cond_node_t * cond, int branch)
{
	int error = 0;
	qpol_syn_rule_key_t key = { 0, 0, 0, 0, NULL };
	struct qpol_syn_rule *new_rule = NULL;
	ebitmap_t source_types, source_types2, target_types, target_types2;
	ebitmap_node_t *snode = NULL, *tnode = NULL;
	unsigned int i, j;
	class_perm_node_t *class_node = NULL;

	if (!(new_rule = malloc(sizeof(struct qpol_syn_rule)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	new_rule->rule = rule;
	new_rule->cond = cond;
	new_rule->cond_branch = branch;

	policy->ext->syn_rule_master_list[policy->ext->master_list_sz] = new_rule;
	policy->ext->master_list_sz++;

	if (type_set_expand(&rule->stypes, &source_types, &policy->p->p, 0) ||
	    type_set_expand(&rule->stypes, &source_types2, &policy->p->p, 1)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	if (type_set_expand(&rule->ttypes, &target_types, &policy->p->p, 0) ||
	    type_set_expand(&rule->ttypes, &target_types2, &policy->p->p, 1)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	if (ebitmap_union(&source_types, &source_types2) || ebitmap_union(&target_types, &target_types2)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	ebitmap_for_each_bit(&source_types, snode, i) {
		if (!ebitmap_get_bit(&source_types, i))
			continue;
		if (rule->flags & RULE_SELF) {
			for (class_node = rule->perms; class_node; class_node = class_node->next) {
				key.rule_type = rule->specified;
				key.source_val = key.target_val = i + 1;
				key.class_val = class_node->tclass;
				key.cond = cond;
				if (qpol_syn_rule_table_insert_entry(policy, table, &key, new_rule))
					goto err;
			}
		}
		ebitmap_for_each_bit(&target_types, tnode, j) {
			if (!ebitmap_get_bit(&target_types, j))
				continue;
			for (class_node = rule->perms; class_node; class_node = class_node->next) {
				key.rule_type = rule->specified;
				key.source_val = i + 1;
				key.target_val = j + 1;
				key.class_val = class_node->tclass;
				key.cond = cond;
				if (qpol_syn_rule_table_insert_entry(policy, table, &key, new_rule))
					goto err;
			}
		}
	}

	ebitmap_destroy(&source_types);
	ebitmap_destroy(&source_types2);
	ebitmap_destroy(&target_types);
	ebitmap_destroy(&target_types2);
	return 0;

      err:
	ebitmap_destroy(&source_types);
	ebitmap_destroy(&source_types2);
	ebitmap_destroy(&target_types);
	ebitmap_destroy(&target_types2);
	return -1;
}

int qpol_policy_build_syn_rule_table(qpol_policy_t * policy)
{
	int error = 0, created = 0;
	avrule_block_t *cur_block = NULL;
	avrule_decl_t *decl = NULL;
	avrule_t *cur_rule = NULL;
	cond_node_t *cur_cond = NULL, *remapped_cond;

	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!policy->ext) {
		policy->ext = calloc(1, sizeof(qpol_extended_image_t));
		if (!policy->ext) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
	}

	if (policy->ext->syn_rule_table)
		return 0;	       /* already built */

	policy->ext->syn_rule_table = calloc(1, sizeof(qpol_syn_rule_table_t));
	if (!policy->ext->syn_rule_table) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	policy->ext->syn_rule_table->buckets = calloc(QPOL_SYN_RULE_TABLE_SIZE, sizeof(qpol_syn_rule_node_t *));
	if (!policy->ext->syn_rule_table->buckets) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	policy->ext->master_list_sz = 0;
	for (cur_block = policy->p->p.global; cur_block; cur_block = cur_block->next) {
		decl = cur_block->enabled;
		if (!decl)
			continue;

		for (cur_rule = decl->avrules; cur_rule; cur_rule = cur_rule->next) {
			policy->ext->master_list_sz++;
		}
		for (cur_cond = decl->cond_list; cur_cond; cur_cond = cur_cond->next) {
			for (cur_rule = cur_cond->avtrue_list; cur_rule; cur_rule = cur_rule->next) {
				policy->ext->master_list_sz++;
			}
			for (cur_rule = cur_cond->avfalse_list; cur_rule; cur_rule = cur_rule->next) {
				policy->ext->master_list_sz++;
			}
		}
	}

	if (policy->ext->master_list_sz == 0) {
		policy->ext->syn_rule_master_list = NULL;
		return 0;	       /* policy is not a source policy */
	}

	INFO(policy, "%s", "Building syntactic rules tables.");

	policy->ext->syn_rule_master_list = calloc(policy->ext->master_list_sz, sizeof(struct qpol_syn_rule *));
	if (!policy->ext->syn_rule_master_list) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	/* reset size as it will represent the current number of elements inserted */
	policy->ext->master_list_sz = 0;

	for (cur_block = policy->p->p.global; cur_block; cur_block = cur_block->next) {
		decl = cur_block->enabled;
		if (!decl)
			continue;

		for (cur_rule = decl->avrules; cur_rule; cur_rule = cur_rule->next) {
			if (qpol_syn_rule_table_insert_sepol_avrule(policy, policy->ext->syn_rule_table, cur_rule, NULL, 0)) {
				error = errno;
				goto err;
			}
		}
		for (cur_cond = decl->cond_list; cur_cond; cur_cond = cur_cond->next) {
			/* convert the cond within an avrule_decl to
			 * the expanded cond */
			remapped_cond = cond_node_find(&policy->p->p, cur_cond, policy->p->p.cond_list, &created);
			if (created || !remapped_cond) {
				cond_node_destroy(remapped_cond);
				error = EIO;
				ERR(policy, "%s", "Inconsistent conditional records");
				assert(0);
				goto err;
			}
			for (cur_rule = cur_cond->avtrue_list; cur_rule; cur_rule = cur_rule->next) {
				if (qpol_syn_rule_table_insert_sepol_avrule
				    (policy, policy->ext->syn_rule_table, cur_rule, remapped_cond, 0)) {
					error = errno;
					goto err;
				}
			}
			for (cur_rule = cur_cond->avfalse_list; cur_rule; cur_rule = cur_rule->next) {
				if (qpol_syn_rule_table_insert_sepol_avrule
				    (policy, policy->ext->syn_rule_table, cur_rule, remapped_cond, 1)) {
					error = errno;
					goto err;
				}
			}
		}
	}

#ifdef SETOOLS_DEBUG
	/*
	 * Debugging code to measure the how well the syntactic rules
	 * are being hashed.  Calculate the min, max, and std
	 * deviation.
	 */
	size_t bucket;
	float o2 = 0.0f;
	long total_entries = 0;
	for (bucket = 0; bucket < QPOL_SYN_RULE_TABLE_SIZE; bucket++) {
		qpol_syn_rule_node_t *n = policy->ext->syn_rule_table->buckets[bucket];
		while (n != NULL) {
			total_entries++;
			n = n->next;
		}
	}
	float expected_value = total_entries * 1.0f / QPOL_SYN_RULE_TABLE_SIZE;
	size_t min_items = total_entries;
	size_t max_items = 0;
	for (bucket = 0; bucket < QPOL_SYN_RULE_TABLE_SIZE; bucket++) {
		size_t num_items = 0;
		qpol_syn_rule_node_t *n = policy->ext->syn_rule_table->buckets[bucket];
		while (n != NULL) {
			num_items++;
			n = n->next;
		}
		if (num_items > max_items) {
			max_items = num_items;
		}
		if (num_items < min_items) {
			min_items = num_items;
		}
		o2 += (num_items - expected_value) * (num_items - expected_value);
	}
	float stddev = sqrtf(o2 / (QPOL_SYN_RULE_TABLE_SIZE - 1));
	fprintf(stderr, "libqpol synrule table %d bits:  total entries %lu, expected %g\n", QPOL_SYN_RULE_TABLE_BITS, total_entries,
		expected_value);
	fprintf(stderr, "                        min %zd, max %zd, stddev %g\n", min_items, max_items, stddev);
#endif

	return 0;

      err:
	if (policy->ext)
		qpol_syn_rule_table_destroy(&policy->ext->syn_rule_table);
	errno = error;
	return -1;
}

/**
 *  Free all memory used by a qpol extended image and set it to NULL.
 *  @param ext The extended image to destroy.
 */
void qpol_extended_image_destroy(qpol_extended_image_t ** ext)
{
	size_t i = 0;

	if (!ext || !(*ext))
		return;

	qpol_syn_rule_table_destroy(&((*ext)->syn_rule_table));

	for (i = 0; i < (*ext)->master_list_sz; i++) {
		qpol_syn_rule_destroy(&((*ext)->syn_rule_master_list[i]));
	}
	free((*ext)->syn_rule_master_list);

	free(*ext);
	*ext = NULL;
}

int policy_extend(qpol_policy_t * policy)
{
	int retv, error;
	policydb_t *db = NULL;

	if (policy == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	db = &policy->p->p;

	retv = qpol_policy_remove_bogus_aliases(policy);
	if (retv) {
		error = errno;
		goto err;
	}
	if (db->attr_type_map) {
		retv = qpol_policy_build_attrs_from_map(policy);
		if (retv) {
			error = errno;
			goto err;
		}
		if (db->policy_type == POLICY_KERN) {
			retv = qpol_policy_fill_attr_holes(policy);
			if (retv) {
				error = errno;
				goto err;
			}
		}
	}
	retv = qpol_policy_add_isid_names(policy);
	if (retv) {
		error = errno;
		goto err;
	}
	retv = qpol_policy_add_object_r(policy);
	if (retv) {
		error = errno;
		goto err;
	}

	if ((policy->options & QPOL_POLICY_OPTION_MATCH_SYSTEM) && qpol_policy_match_system(policy)) {
		error = errno;
		goto err;
	}

	if (policy->options & QPOL_POLICY_OPTION_NO_RULES)
		return STATUS_SUCCESS;

	retv = qpol_policy_add_cond_rule_traceback(policy);
	if (retv) {
		error = errno;
		goto err;
	}

	return STATUS_SUCCESS;

      err:
	/* no need to call ERR here as it will already have been called */
	qpol_extended_image_destroy(&policy->ext);
	errno = error;
	return STATUS_ERR;
}

typedef struct syn_rule_state
{
	qpol_syn_rule_node_t *node;
	qpol_syn_rule_list_t *cur;
} syn_rule_state_t;

static int syn_rule_state_end(const qpol_iterator_t * iter)
{
	syn_rule_state_t *srs = NULL;

	if (!iter || !(srs = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return (srs->cur ? 0 : 1);
}

static void *syn_rule_state_get_cur(const qpol_iterator_t * iter)
{
	syn_rule_state_t *srs = NULL;

	if (!iter || !(srs = qpol_iterator_state(iter)) || qpol_iterator_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	return srs->cur->rule;
}

static int syn_rule_state_next(qpol_iterator_t * iter)
{
	syn_rule_state_t *srs = NULL;

	if (!iter || !(srs = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}
	if (qpol_iterator_end(iter)) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	srs->cur = srs->cur->next;

	return STATUS_SUCCESS;
}

static size_t syn_rule_state_size(const qpol_iterator_t * iter)
{
	size_t count = 0;
	qpol_syn_rule_list_t *tmp = NULL;
	syn_rule_state_t *srs = NULL;

	if (!iter || !(srs = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	for (tmp = srs->node->rules; tmp; tmp = tmp->next)
		count++;

	return count;
}

int qpol_avrule_get_syn_avrule_iter(const qpol_policy_t * policy, const struct qpol_avrule *rule, qpol_iterator_t ** iter)
{
	qpol_syn_rule_key_t *key = NULL;
	const qpol_type_t *tmp_type;
	const qpol_class_t *tmp_class;
	const qpol_cond_t *tmp_cond;
	syn_rule_state_t *srs = NULL;
	uint32_t tmp_val;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !policy->ext || !rule || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	/* build key */
	if (!(key = calloc(1, sizeof(qpol_syn_rule_key_t)))) {
		error = errno;
		ERR(policy, "%S", strerror(error));
		goto err;
	}

	if (qpol_avrule_get_rule_type(policy, rule, &tmp_val)) {
		error = errno;
		goto err;
	}
	key->rule_type = (tmp_val == QPOL_RULE_DONTAUDIT ? (AVRULE_AUDITDENY | AVRULE_DONTAUDIT) : tmp_val);

	if (qpol_avrule_get_source_type(policy, rule, &tmp_type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_value(policy, tmp_type, &tmp_val)) {
		error = errno;
		goto err;
	}
	key->source_val = tmp_val;

	if (qpol_avrule_get_target_type(policy, rule, &tmp_type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_value(policy, tmp_type, &tmp_val)) {
		error = errno;
		goto err;
	}
	key->target_val = tmp_val;

	if (qpol_avrule_get_object_class(policy, rule, &tmp_class)) {
		error = errno;
		goto err;
	}
	if (qpol_class_get_value(policy, tmp_class, &tmp_val)) {
		error = errno;
		goto err;
	}
	key->class_val = tmp_val;

	if (qpol_avrule_get_cond(policy, rule, &tmp_cond)) {
		error = errno;
		goto err;
	}
	key->cond = (cond_node_t *) tmp_cond;

	/* build state object */
	if (!(srs = calloc(1, sizeof(syn_rule_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	srs->node = qpol_syn_rule_table_find_node_by_key(policy->ext->syn_rule_table, key);
	if (!srs->node) {
		ERR(policy, "%s", "Unable to locate syntactic rules for semantic av rule");
		errno = ENOENT;
		goto err;
	}
	srs->cur = srs->node->rules;

	if (qpol_iterator_create(policy, (void *)srs,
				 syn_rule_state_get_cur, syn_rule_state_next, syn_rule_state_end, syn_rule_state_size, free, iter))
	{
		error = errno;
		goto err;
	}

	free(key);

	return 0;

      err:
	free(key);
	free(srs);
	errno = error;
	return -1;
}

int qpol_terule_get_syn_terule_iter(const qpol_policy_t * policy, const struct qpol_terule *rule, qpol_iterator_t ** iter)
{
	qpol_syn_rule_key_t *key = NULL;
	const qpol_type_t *tmp_type;
	const qpol_class_t *tmp_class;
	const qpol_cond_t *tmp_cond;
	syn_rule_state_t *srs = NULL;
	uint32_t tmp_val;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!policy || !policy->ext || !rule || !iter) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	/* build key */
	if (!(key = calloc(1, sizeof(qpol_syn_rule_key_t)))) {
		error = errno;
		ERR(policy, "%S", strerror(error));
		goto err;
	}

	if (qpol_terule_get_rule_type(policy, rule, &tmp_val)) {
		error = errno;
		goto err;
	}
	key->rule_type = tmp_val;

	if (qpol_terule_get_source_type(policy, rule, &tmp_type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_value(policy, tmp_type, &tmp_val)) {
		error = errno;
		goto err;
	}
	key->source_val = tmp_val;

	if (qpol_terule_get_target_type(policy, rule, &tmp_type)) {
		error = errno;
		goto err;
	}
	if (qpol_type_get_value(policy, tmp_type, &tmp_val)) {
		error = errno;
		goto err;
	}
	key->target_val = tmp_val;

	if (qpol_terule_get_object_class(policy, rule, &tmp_class)) {
		error = errno;
		goto err;
	}
	if (qpol_class_get_value(policy, tmp_class, &tmp_val)) {
		error = errno;
		goto err;
	}
	key->class_val = tmp_val;

	if (qpol_terule_get_cond(policy, rule, &tmp_cond)) {
		error = errno;
		goto err;
	}
	key->cond = (cond_node_t *) tmp_cond;

	/* build state object */
	if (!(srs = calloc(1, sizeof(syn_rule_state_t)))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}

	srs->node = qpol_syn_rule_table_find_node_by_key(policy->ext->syn_rule_table, key);
	if (!srs->node) {
		ERR(policy, "%s", "Unable to locate syntactic rules for semantic te rule");
		error = ENOENT;
		goto err;
	}
	srs->cur = srs->node->rules;

	if (qpol_iterator_create(policy, (void *)srs,
				 syn_rule_state_get_cur, syn_rule_state_next, syn_rule_state_end, syn_rule_state_size, free, iter))
	{
		error = errno;
		goto err;
	}

	free(key);

	return 0;

      err:
	free(key);
	free(srs);
	errno = error;
	return -1;
}
