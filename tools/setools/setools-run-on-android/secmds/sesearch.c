/**
 *  @file
 *  Command line tool to search TE rules.
 *
 *  @author Frank Mayer  mayerf@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Paul Rosenfeld  prosenfeld@tresys.com
 *
 *  Copyright (C) 2003-2009 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

/* libapol */
#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>
#include <apol/vector.h>

/* libqpol*/
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include <qpol/syn_rule_query.h>
#include <qpol/util.h>

/* other */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2009 Tresys Technology, LLC"

static char *policy_file = NULL;

enum opt_values
{
	RULE_NEVERALLOW = 256, RULE_AUDIT, RULE_AUDITALLOW, RULE_DONTAUDIT,
	RULE_ROLE_ALLOW, RULE_ROLE_TRANS, RULE_RANGE_TRANS, RULE_ALL,
	EXPR_ROLE_SOURCE, EXPR_ROLE_TARGET
};

static struct option const longopts[] = {
	{"allow", no_argument, NULL, 'A'},
	{"neverallow", no_argument, NULL, RULE_NEVERALLOW},
	{"audit", no_argument, NULL, RULE_AUDIT},
	{"auditallow", no_argument, NULL, RULE_AUDITALLOW},
	{"dontaudit", no_argument, NULL, RULE_DONTAUDIT},
	{"type", no_argument, NULL, 'T'},
	{"role_allow", no_argument, NULL, RULE_ROLE_ALLOW},
	{"role_trans", no_argument, NULL, RULE_ROLE_TRANS},
	{"range_trans", no_argument, NULL, RULE_RANGE_TRANS},
	{"all", no_argument, NULL, RULE_ALL},

	{"source", required_argument, NULL, 's'},
	{"target", required_argument, NULL, 't'},
	{"default", required_argument, NULL, 'D'},
	{"role_source", required_argument, NULL, EXPR_ROLE_SOURCE},
	{"role_target", required_argument, NULL, EXPR_ROLE_TARGET},
	{"class", required_argument, NULL, 'c'},
	{"perm", required_argument, NULL, 'p'},
	{"bool", required_argument, NULL, 'b'},

	{"direct", no_argument, NULL, 'd'},
	{"regex", no_argument, NULL, 'R'},
	{"linenum", no_argument, NULL, 'n'},
	{"semantic", no_argument, NULL, 'S'},
	{"show_cond", no_argument, NULL, 'C'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{NULL, 0, NULL, 0}
};

typedef struct options
{
	char *src_name;
	char *tgt_name;
	char *default_name;
	char *src_role_name;
	char *tgt_role_name;
	char *class_name;
	char *permlist;
	char *bool_name;
	apol_vector_t *class_vector;
	bool all;
	bool lineno;
	bool semantic;
	bool indirect;
	bool allow;
	bool nallow;
	bool auditallow;
	bool dontaudit;
	bool type;
	bool rtrans;
	bool role_allow;
	bool role_trans;
	bool useregex;
	bool show_cond;
	apol_vector_t *perm_vector;
} options_t;

void usage(const char *program_name, int brief)
{
	printf("Usage: %s [OPTIONS] RULE_TYPE [RULE_TYPE ...] [EXPESSION] [POLICY ...]\n\n", program_name);
	if (brief) {
		printf("\tTry %s --help for more help.\n\n", program_name);
		return;
	}
	printf("Search the rules in a SELinux policy.\n\n");
	printf("RULE_TYPES:\n");
	printf("  -A, --allow               allow rules\n");
	printf("  --neverallow              neverallow rules\n");
	printf("  --auditallow              auditallow rules\n");
	printf("  --dontaudit               dontaudit rules\n");
	printf("  -T, --type                type_trans, type_member, and type_change\n");
	printf("  --role_allow              role allow rules\n");
	printf("  --role_trans              role_transition rules\n");
	printf("  --range_trans             range_transition rules\n");
	printf("  --all                     all rules regardless of type, class, or perms\n");
	printf("EXPRESSIONS:\n");
	printf("  -s NAME, --source=NAME    rules with type/attribute NAME as source\n");
	printf("  -t NAME, --target=NAME    rules with type/attribute NAME as target\n");
	printf("  -D NAME, --default=NAME   rules with type NAME as default\n");
	printf("  --role_source=NAME        rules with role NAME as source\n");
	printf("  --role_target=NAME        rules with role NAME as target\n");
	printf("  -c NAME, --class=NAME     rules with class NAME as the object class\n");
	printf("  -p P1[,P2,...], --perm=P1[,P2...]\n");
	printf("                            rules with the specified permission\n");
	printf("  -b NAME, --bool=NAME      conditional rules with NAME in the expression\n");
	printf("OPTIONS:\n");
	printf("  -d, --direct              do not search for type's attributes\n");
	printf("  -R, --regex               use regular expression matching\n");
	printf("  -n, --linenum             show line number for each rule if available\n");
	printf("  -S, --semantic            search rules semantically instead of syntactically\n");
	printf("  -C, --show_cond           show conditional expression for conditional rules\n");
	printf("  -h, --help                print this help text and exit\n");
	printf("  -V, --version             print version information and exit\n");
	printf("\n");
	printf("If no expression is specified, then all rules are shown.\n");
	printf("\n");
	printf("The default source policy, or if that is unavailable the default binary\n");
	printf("policy, will be opened if no policy is provided.\n\n");
}

static int perform_av_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_avrule_query_t *avq = NULL;
	unsigned int rules = 0;
	int error = 0;
	char *tmp = NULL, *tok = NULL, *s = NULL;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->all && !opt->allow && !opt->nallow && !opt->auditallow && !opt->dontaudit) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	avq = apol_avrule_query_create();
	if (!avq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	if (opt->allow || opt->all)
		rules |= QPOL_RULE_ALLOW;
	if (opt->nallow || opt->all)	// Add this regardless of policy capabilities
		rules |= QPOL_RULE_NEVERALLOW;
	if (opt->auditallow || opt->all)
		rules |= QPOL_RULE_AUDITALLOW;
	if (opt->dontaudit || opt->all)
		rules |= QPOL_RULE_DONTAUDIT;
	if (rules != 0)					// Setting rules = 0 means you want all the rules
		apol_avrule_query_set_rules(policy, avq, rules);
	apol_avrule_query_set_regex(policy, avq, opt->useregex);
	if (opt->src_name)
		apol_avrule_query_set_source(policy, avq, opt->src_name, opt->indirect);
	if (opt->tgt_name)
		apol_avrule_query_set_target(policy, avq, opt->tgt_name, opt->indirect);
	if (opt->bool_name)
		apol_avrule_query_set_bool(policy, avq, opt->bool_name);
	if (opt->class_name) {
		if (opt->class_vector == NULL) {
			if (apol_avrule_query_append_class(policy, avq, opt->class_name)) {
				error = errno;
				goto err;
			}
		} else {
			for (size_t i = 0; i < apol_vector_get_size(opt->class_vector); ++i) {
				char *class_name;
				class_name = apol_vector_get_element(opt->class_vector, i);
				if (!class_name)
					continue;
				if (apol_avrule_query_append_class(policy, avq, class_name)) {
					error = errno;
					goto err;
				}
			}
		}
	}

	if (opt->permlist) {
		tmp = strdup(opt->permlist);
		for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
			if (apol_avrule_query_append_perm(policy, avq, tok)) {
				error = errno;
				goto err;
			}
			if ((s = strdup(tok)) == NULL || apol_vector_append(opt->perm_vector, s) < 0) {
				error = errno;
				goto err;
			}
			s = NULL;
		}
		free(tmp);
	}

	if (!(opt->semantic) && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (apol_syn_avrule_get_by_query(policy, avq, v)) {
			error = errno;
			goto err;
		}
	} else {
		if (apol_avrule_get_by_query(policy, avq, v)) {
			error = errno;
			goto err;
		}
	}

	apol_avrule_query_destroy(&avq);
	return 0;

      err:
	apol_vector_destroy(v);
	apol_avrule_query_destroy(&avq);
	free(tmp);
	free(s);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_syn_av_results(const apol_policy_t * policy, const options_t * opt, const apol_vector_t * v)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	const apol_vector_t *syn_list = NULL;
	const qpol_syn_avrule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	const qpol_cond_t *cond = NULL;
	uint32_t enabled = 0, is_true = 0;
	unsigned long lineno = 0;

	if (!policy || !v)
		return;

	syn_list = v;
	if (!(num_rules = apol_vector_get_size(syn_list)))
		goto cleanup;

	fprintf(stdout, "Found %zd syntactic av rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		rule = apol_vector_get_element(syn_list, i);
		enable_char = branch_char = ' ';
		if (opt->show_cond) {
			if (qpol_syn_avrule_get_cond(q, rule, &cond))
				goto cleanup;
			if (cond) {
				if (qpol_syn_avrule_get_is_enabled(q, rule, &enabled) < 0 || qpol_cond_eval(q, cond, &is_true) < 0)
					goto cleanup;
				tmp = apol_cond_expr_render(policy, cond);
				enable_char = (enabled ? 'E' : 'D');
				branch_char = ((is_true && enabled) || (!is_true && !enabled) ? 'T' : 'F');
				if (asprintf(&expr, "[ %s ]", tmp) < 0) {
					expr = NULL;
					goto cleanup;
				}
				free(tmp);
				tmp = NULL;
				if (!expr)
					goto cleanup;
			}
		}
		if (!(rule_str = apol_syn_avrule_render(policy, rule)))
			goto cleanup;
		if (opt->lineno) {
			if (qpol_syn_avrule_get_lineno(q, rule, &lineno))
				goto cleanup;
			fprintf(stdout, "%c%c [%7lu] %s %s\n", enable_char, branch_char, lineno, rule_str, expr ? expr : "");
		} else {
			fprintf(stdout, "%c%c %s %s\n", enable_char, branch_char, rule_str, expr ? expr : "");
		}
		free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}

      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
}

static void print_av_results(const apol_policy_t * policy, const options_t * opt, const apol_vector_t * v)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	const qpol_avrule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	qpol_iterator_t *iter = NULL;
	const qpol_cond_t *cond = NULL;
	uint32_t enabled = 0, list = 0;

	if (!policy || !v)
		return;

	if (!(num_rules = apol_vector_get_size(v)))
		return;

	fprintf(stdout, "Found %zd semantic av rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		enable_char = branch_char = ' ';
		if (!(rule = apol_vector_get_element(v, i)))
			goto cleanup;
		if (opt->show_cond) {
			if (qpol_avrule_get_cond(q, rule, &cond))
				goto cleanup;
			if (qpol_avrule_get_is_enabled(q, rule, &enabled))
				goto cleanup;
			if (cond) {
				if (qpol_avrule_get_which_list(q, rule, &list))
					goto cleanup;
				tmp = apol_cond_expr_render(policy, cond);
				qpol_iterator_destroy(&iter);
				enable_char = (enabled ? 'E' : 'D');
				branch_char = (list ? 'T' : 'F');
				if (asprintf(&expr, "[ %s ]", tmp) < 0) {
					expr = NULL;
					goto cleanup;
				}
				free(tmp);
				tmp = NULL;
				if (!expr)
					goto cleanup;
			}
		}
		if (!(rule_str = apol_avrule_render(policy, rule)))
			goto cleanup;
		fprintf(stdout, "%c%c %s %s\n", enable_char, branch_char, rule_str, expr ? expr : "");
		free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}

      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
}

static int perform_te_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_terule_query_t *teq = NULL;
	unsigned int rules = 0;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (opt->all || opt->type) {
		rules = (QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER);
	} else {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	teq = apol_terule_query_create();
	if (!teq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_terule_query_set_rules(policy, teq, rules);
	apol_terule_query_set_regex(policy, teq, opt->useregex);
	if (opt->src_name)
		apol_terule_query_set_source(policy, teq, opt->src_name, opt->indirect);
	if (opt->tgt_name)
		apol_terule_query_set_target(policy, teq, opt->tgt_name, opt->indirect);
	if (opt->bool_name)
		apol_terule_query_set_bool(policy, teq, opt->bool_name);
	if (opt->default_name)
		apol_terule_query_set_default(policy, teq, opt->default_name);
	if (opt->class_name) {
		if (opt->class_vector == NULL) {
			if (apol_terule_query_append_class(policy, teq, opt->class_name)) {
				error = errno;
				goto err;
			}
		} else {
			for (size_t i = 0; i < apol_vector_get_size(opt->class_vector); ++i) {
				char *class_name;
				class_name = apol_vector_get_element(opt->class_vector, i);
				if (!class_name)
					continue;
				if (apol_terule_query_append_class(policy, teq, class_name)) {
					error = errno;
					goto err;
				}
			}
		}
	}

	if (!(opt->semantic) && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (apol_syn_terule_get_by_query(policy, teq, v)) {
			error = errno;
			goto err;
		}
	} else {
		if (apol_terule_get_by_query(policy, teq, v)) {
			error = errno;
			goto err;
		}
	}

	apol_terule_query_destroy(&teq);
	return 0;

      err:
	apol_vector_destroy(v);
	apol_terule_query_destroy(&teq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_syn_te_results(const apol_policy_t * policy, const options_t * opt, const apol_vector_t * v)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	const apol_vector_t *syn_list = NULL;
	const qpol_syn_terule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	const qpol_cond_t *cond = NULL;
	uint32_t enabled = 0, is_true = 0;
	unsigned long lineno = 0;

	if (!policy || !v)
		return;

	syn_list = v;
	if (!(num_rules = apol_vector_get_size(syn_list)))
		goto cleanup;

	fprintf(stdout, "Found %zd syntactic te rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		rule = apol_vector_get_element(syn_list, i);
		enable_char = branch_char = ' ';
		if (opt->show_cond) {
			if (qpol_syn_terule_get_cond(q, rule, &cond))
				goto cleanup;
			if (cond) {
				if (qpol_syn_terule_get_is_enabled(q, rule, &enabled) < 0 || qpol_cond_eval(q, cond, &is_true) < 0)
					goto cleanup;
				tmp = apol_cond_expr_render(policy, cond);
				enable_char = (enabled ? 'E' : 'D');
				branch_char = ((is_true && enabled) || (!is_true && !enabled) ? 'T' : 'F');
				if (asprintf(&expr, "[ %s ]", tmp) < 0) {
					expr = NULL;
					goto cleanup;
				}
				free(tmp);
				tmp = NULL;
				if (!expr)
					goto cleanup;
			}
		}
		if (!(rule_str = apol_syn_terule_render(policy, rule)))
			goto cleanup;
		if (opt->lineno) {
			if (qpol_syn_terule_get_lineno(q, rule, &lineno))
				goto cleanup;
			fprintf(stdout, "%c%c [%7lu] %s %s\n", enable_char, branch_char, lineno, rule_str, expr ? expr : "");
		} else {
			fprintf(stdout, "%c%c %s %s\n", enable_char, branch_char, rule_str, expr ? expr : "");
		}
		free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}

      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
}

static void print_te_results(const apol_policy_t * policy, const options_t * opt, const apol_vector_t * v)
{
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	const qpol_terule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	qpol_iterator_t *iter = NULL;
	const qpol_cond_t *cond = NULL;
	uint32_t enabled = 0, list = 0;

	if (!policy || !v)
		goto cleanup;

	if (!(num_rules = apol_vector_get_size(v)))
		goto cleanup;

	fprintf(stdout, "Found %zd semantic te rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		enable_char = branch_char = ' ';
		if (!(rule = apol_vector_get_element(v, i)))
			goto cleanup;
		if (opt->show_cond) {
			if (qpol_terule_get_cond(q, rule, &cond))
				goto cleanup;
			if (qpol_terule_get_is_enabled(q, rule, &enabled))
				goto cleanup;
			if (cond) {
				if (qpol_terule_get_which_list(q, rule, &list))
					goto cleanup;
				if (qpol_cond_get_expr_node_iter(q, cond, &iter))
					goto cleanup;
				tmp = apol_cond_expr_render(policy, cond);
				qpol_iterator_destroy(&iter);
				enable_char = (enabled ? 'E' : 'D');
				branch_char = (list ? 'T' : 'F');
				if (asprintf(&expr, "[ %s ]", tmp) < 0) {
					expr = NULL;
					goto cleanup;
				}
				free(tmp);
				tmp = NULL;
				if (!expr)
					goto cleanup;
			}
		}
		if (!(rule_str = apol_terule_render(policy, rule)))
			goto cleanup;
		fprintf(stdout, "%c%c %s %s\n", enable_char, branch_char, rule_str, expr ? expr : "");
		free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}

      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
}

static int perform_ft_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_filename_trans_query_t *ftq = NULL;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->type && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	ftq = apol_filename_trans_query_create();
	if (!ftq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_filename_trans_query_set_regex(policy, ftq, opt->useregex);
	if (opt->src_name) {
		if (apol_filename_trans_query_set_source(policy, ftq, opt->src_name, opt->indirect)) {
			error = errno;
			goto err;
		}
	}

	if (opt->tgt_name) {
		if (apol_filename_trans_query_set_target(policy, ftq, opt->tgt_name, opt->indirect)) {
			error = errno;
			goto err;
		}
	}

	if (opt->default_name) {
		if (apol_filename_trans_query_set_default(policy, ftq, opt->default_name)) {
			error = errno;
			goto err;
		}
	}

	if (opt->class_name) {
		if (opt->class_vector == NULL) {
			if (apol_filename_trans_query_append_class(policy, ftq, opt->class_name)) {
				error = errno;
				goto err;
			}
		} else {
			for (size_t i = 0; i < apol_vector_get_size(opt->class_vector); ++i) {
				char *class_name;
				class_name = apol_vector_get_element(opt->class_vector, i);
				if (!class_name)
					continue;
				if (apol_filename_trans_query_append_class(policy, ftq, class_name)) {
					error = errno;
					goto err;
				}
			}
		}
	}

	if (apol_filename_trans_get_by_query(policy, ftq, v)) {
		error = errno;
		goto err;
	}

	apol_filename_trans_query_destroy(&ftq);
	return 0;

      err:
	apol_vector_destroy(v);
	apol_filename_trans_query_destroy(&ftq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_ft_results(const apol_policy_t * policy, const options_t * opt, const apol_vector_t * v)
{
	size_t i, num_filename_trans = 0;
	const qpol_filename_trans_t *filename_trans = NULL;
	char *filename_trans_str = NULL;
	qpol_iterator_t *iter = NULL;

	if (!(num_filename_trans = apol_vector_get_size(v)))
		goto cleanup;

	fprintf(stdout, "Found %zd named file transition rules:\n", num_filename_trans);

	for (i = 0; i < num_filename_trans; i++) {
		if (!(filename_trans = apol_vector_get_element(v, i)))
			goto cleanup;

		if (!(filename_trans_str = apol_filename_trans_render(policy, filename_trans)))
			goto cleanup;
		fprintf(stdout, "%s\n", filename_trans_str);
		free(filename_trans_str);
		filename_trans_str = NULL;
	}

      cleanup:
	free(filename_trans_str);
}

static int perform_ra_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_role_allow_query_t *raq = NULL;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->role_allow && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	raq = apol_role_allow_query_create();
	if (!raq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_role_allow_query_set_regex(policy, raq, opt->useregex);
	if (opt->src_role_name) {
		if (apol_role_allow_query_set_source(policy, raq, opt->src_role_name)) {
			error = errno;
			goto err;
		}
	}
	if (opt->tgt_role_name)
		if (apol_role_allow_query_set_target(policy, raq, opt->tgt_role_name)) {
			error = errno;
			goto err;
		}

	if (apol_role_allow_get_by_query(policy, raq, v)) {
		error = errno;
		goto err;
	}

	apol_role_allow_query_destroy(&raq);
	return 0;

      err:
	apol_vector_destroy(v);
	apol_role_allow_query_destroy(&raq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_ra_results(const apol_policy_t * policy, const options_t * opt __attribute__ ((unused)), const apol_vector_t * v)
{
	size_t i, num_rules = 0;
	const qpol_role_allow_t *rule = NULL;
	char *tmp = NULL;

	if (!policy || !v)
		return;

	if (!(num_rules = apol_vector_get_size(v)))
		return;

	fprintf(stdout, "Found %zd role allow rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		if (!(rule = apol_vector_get_element(v, i)))
			break;
		if (!(tmp = apol_role_allow_render(policy, rule)))
			break;
		fprintf(stdout, "   %s\n", tmp);
		free(tmp);
		tmp = NULL;
	}
}

static int perform_rt_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_role_trans_query_t *rtq = NULL;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->role_trans && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	rtq = apol_role_trans_query_create();
	if (!rtq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_role_trans_query_set_regex(policy, rtq, opt->useregex);
	if (opt->src_role_name) {
		if (apol_role_trans_query_set_source(policy, rtq, opt->src_role_name)) {
			error = errno;
			goto err;
		}
	}
	if (opt->tgt_name) {
		if (apol_role_trans_query_set_target(policy, rtq, opt->tgt_name, opt->indirect)) {
			error = errno;
			goto err;
		}
	}

	if (opt->default_name) {
		if (apol_role_trans_query_set_default(policy, rtq, opt->default_name)) {
			error = errno;
			goto err;
		}
	}

	if (apol_role_trans_get_by_query(policy, rtq, v)) {
		error = errno;
		goto err;
	}

	apol_role_trans_query_destroy(&rtq);
	return 0;

      err:
	apol_vector_destroy(v);
	apol_role_trans_query_destroy(&rtq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_rt_results(const apol_policy_t * policy, const options_t * opt __attribute__ ((unused)), const apol_vector_t * v)
{
	size_t i, num_rules = 0;
	const qpol_role_trans_t *rule = NULL;
	char *tmp = NULL;

	if (!policy || !v)
		return;

	if (!(num_rules = apol_vector_get_size(v)))
		return;

	fprintf(stdout, "Found %zd role_transition rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		if (!(rule = apol_vector_get_element(v, i)))
			break;
		if (!(tmp = apol_role_trans_render(policy, rule)))
			break;
		fprintf(stdout, "   %s\n", tmp);
		free(tmp);
		tmp = NULL;
	}
}

static int perform_range_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_range_trans_query_t *rtq = NULL;
	int error = 0;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->rtrans && !opt->all) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	rtq = apol_range_trans_query_create();
	if (!rtq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	apol_range_trans_query_set_regex(policy, rtq, opt->useregex);
	if (opt->src_name) {
		if (apol_range_trans_query_set_source(policy, rtq, opt->src_name, opt->indirect)) {
			error = errno;
			goto err;
		}
	}
	if (opt->tgt_name) {
		if (apol_range_trans_query_set_target(policy, rtq, opt->tgt_name, opt->indirect)) {
			error = errno;
			goto err;
		}
	}
	if (opt->class_name) {
		if (opt->class_vector == NULL) {
			if (apol_range_trans_query_append_class(policy, rtq, opt->class_name)) {
				error = errno;
				goto err;
			}
		} else {
			for (size_t i = 0; i < apol_vector_get_size(opt->class_vector); ++i) {
				char *class_name;
				class_name = apol_vector_get_element(opt->class_vector, i);
				if (!class_name)
					continue;
				if (apol_range_trans_query_append_class(policy, rtq, class_name)) {
					error = errno;
					goto err;
				}
			}
		}
	}

	if (apol_range_trans_get_by_query(policy, rtq, v)) {
		error = errno;
		goto err;
	}

	apol_range_trans_query_destroy(&rtq);
	return 0;

      err:
	apol_vector_destroy(v);
	apol_range_trans_query_destroy(&rtq);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}

static void print_range_results(const apol_policy_t * policy, const options_t * opt
				__attribute__ ((unused)), const apol_vector_t * v)
{
	size_t i, num_rules = 0;
	const qpol_range_trans_t *rule = NULL;
	char *tmp = NULL;

	if (!policy || !v)
		return;

	if (!(num_rules = apol_vector_get_size(v)))
		return;

	fprintf(stdout, "Found %zd range_transition rules:\n", num_rules);

	for (i = 0; i < num_rules; i++) {
		if (!(rule = apol_vector_get_element(v, i)))
			break;
		if (!(tmp = apol_range_trans_render(policy, rule)))
			break;
		fprintf(stdout, "   %s\n", tmp);
		free(tmp);
		tmp = NULL;
	}
}

int main(int argc, char **argv)
{
	options_t cmd_opts;
	int optc, rt = -1;

	apol_policy_t *policy = NULL;
	apol_vector_t *v = NULL;
	apol_policy_path_t *pol_path = NULL;
	apol_vector_t *mod_paths = NULL;
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;

	memset(&cmd_opts, 0, sizeof(cmd_opts));
	cmd_opts.indirect = true;
	while ((optc = getopt_long(argc, argv, "ATs:t:c:p:b:dD:RnSChV", longopts, NULL)) != -1) {
		switch (optc) {
		case 0:
			break;
		case 's':	       /* source */
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing source type/attribute for -s (--source)\n");
				exit(1);
			}
			cmd_opts.src_name = strdup(optarg);
			if (!cmd_opts.src_name) {
				fprintf(stderr, "%s\n", strerror(errno));
				exit(1);
			}
			break;
		case 't':	       /* target */
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing target type/attribute for -t (--target)\n");
				exit(1);
			}
			cmd_opts.tgt_name = strdup(optarg);
			if (!cmd_opts.tgt_name) {
				fprintf(stderr, "%s\n", strerror(errno));
				exit(1);
			}
			break;
		case 'D':	       /* default */
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing default type for -D (--default)\n");
				exit(1);
			}
			cmd_opts.default_name = strdup(optarg);
			if (!cmd_opts.default_name) {
		
				exit(1);
			}
			break;
		case EXPR_ROLE_SOURCE:
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing source role for --role_source\n");
				exit(1);
			}
			cmd_opts.src_role_name = strdup(optarg);
			if (!cmd_opts.src_role_name) {
				fprintf(stderr, "%s\n", strerror(errno));
				exit(1);
			}
			break;
		case EXPR_ROLE_TARGET:
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing target role for --role_target\n");
				exit(1);
			}
			cmd_opts.tgt_role_name = strdup(optarg);
			if (!cmd_opts.tgt_role_name) {
				fprintf(stderr, "%s\n", strerror(errno));
				exit(1);
			}
			break;
		case 'c':	       /* class */
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing object class for -c (--class)\n");
				exit(1);
			}
			cmd_opts.class_name = strdup(optarg);
			if (!cmd_opts.class_name) {
				fprintf(stderr, "%s\n", strerror(errno));
				exit(1);
			}
			break;
		case 'p':	       /* permission */
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing permissions for -p (--perm)\n");
				exit(1);
			}
			if ((cmd_opts.permlist = strdup(optarg)) == NULL
			    || (cmd_opts.perm_vector = apol_vector_create(free)) == NULL) {
				fprintf(stderr, "%s\n", strerror(errno));
				exit(1);
			}
			break;
		case 'b':
			if (optarg == 0) {
				usage(argv[0], 1);
				printf("Missing boolean for -b (--bool)\n");
				exit(1);
			}
			cmd_opts.bool_name = strdup(optarg);
			if (!cmd_opts.bool_name) {
				fprintf(stderr, "%s\n", strerror(errno));
				exit(1);
			}
			break;
		case 'd':	       /* direct search */
			cmd_opts.indirect = false;
			break;
		case 'R':	       /* use regex */
			cmd_opts.useregex = true;
			break;
		case 'A':	       /* allow */
			cmd_opts.allow = true;
			break;
		case RULE_NEVERALLOW: /* neverallow */
			cmd_opts.nallow = true;
			break;
		case RULE_AUDIT:      /* audit */
			cmd_opts.auditallow = true;
			cmd_opts.dontaudit = true;
			fprintf(stderr, "Use of --audit is deprecated; use --auditallow and --dontaudit instead.\n");
			break;
		case RULE_AUDITALLOW:
			cmd_opts.auditallow = true;
			break;
		case RULE_DONTAUDIT:
			cmd_opts.dontaudit = true;
			break;
		case 'T':	       /* type */
			cmd_opts.type = true;
			break;
		case RULE_ROLE_ALLOW:
			cmd_opts.role_allow = true;
			break;
		case RULE_ROLE_TRANS:
			cmd_opts.role_trans = true;
			break;
		case RULE_RANGE_TRANS:	/* range transition */
			cmd_opts.rtrans = true;
			break;
		case RULE_ALL:	       /* all */
			cmd_opts.all = true;
			break;
		case 'n':	       /* lineno */
			cmd_opts.lineno = true;
			break;
		case 'S':	       /* semantic */
			cmd_opts.semantic = true;
			break;
		case 'C':
			cmd_opts.show_cond = true;
			break;
		case 'h':	       /* help */
			usage(argv[0], 0);
			exit(0);
		case 'V':	       /* version */
			printf("sesearch %s\n%s\n", VERSION, COPYRIGHT_INFO);
			exit(0);
		default:
			usage(argv[0], 1);
			exit(1);
		}
	}

	if (!(cmd_opts.allow || cmd_opts.nallow || cmd_opts.auditallow || cmd_opts.dontaudit || cmd_opts.role_allow ||
	      cmd_opts.type || cmd_opts.rtrans || cmd_opts.role_trans || cmd_opts.all)) {
		usage(argv[0], 1);
		fprintf(stderr, "One of --all, --allow, --neverallow, --auditallow, --dontaudit,\n"
			"--range_trans, --type, --role_allow, or --role_trans must be specified.\n");
		exit(1);
	}

	int pol_opt = 0;
	if (!(cmd_opts.nallow || cmd_opts.all))
		pol_opt |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;

	if (argc - optind < 1) {
		rt = qpol_default_policy_find(&policy_file);
		if (rt < 0) {
			fprintf(stderr, "Default policy search failed: %s\n", strerror(errno));
			exit(1);
		} else if (rt != 0) {
			fprintf(stderr, "No default policy found.\n");
			exit(1);
		}
		pol_opt |= QPOL_POLICY_OPTION_MATCH_SYSTEM;
	} else {
		if ((policy_file = strdup(argv[optind])) == NULL) {
			fprintf(stderr, "%s\n", strerror(errno));
			exit(1);
		}
		optind++;
	}

	if (argc - optind > 0) {
		path_type = APOL_POLICY_PATH_TYPE_MODULAR;
		if (!(mod_paths = apol_vector_create(NULL))) {
			ERR(policy, "%s", strerror(ENOMEM));
			exit(1);
		}
		for (; argc - optind; optind++) {
			if (apol_vector_append(mod_paths, (void *)argv[optind])) {
				ERR(policy, "Error loading module %s", argv[optind]);
				apol_vector_destroy(&mod_paths);
				free(policy_file);
				exit(1);
			}
		}
	} else if (apol_file_is_policy_path_list(policy_file) > 0) {
		pol_path = apol_policy_path_create_from_file(policy_file);
		if (!pol_path) {
			ERR(policy, "%s", "invalid policy list");
			free(policy_file);
			exit(1);
		}
	}

	if (!pol_path)
		pol_path = apol_policy_path_create(path_type, policy_file, mod_paths);
	if (!pol_path) {
		ERR(policy, "%s", strerror(ENOMEM));
		free(policy_file);
		apol_vector_destroy(&mod_paths);
		exit(1);
	}
	free(policy_file);
	apol_vector_destroy(&mod_paths);

	policy = apol_policy_create_from_policy_path(pol_path, pol_opt, NULL, NULL);
	if (!policy) {
		ERR(policy, "%s", strerror(errno));
		apol_policy_path_destroy(&pol_path);
		exit(1);
	}
	/* handle regex for class name */
	if (cmd_opts.useregex && cmd_opts.class_name != NULL) {
		cmd_opts.class_vector = apol_vector_create(NULL);
		apol_vector_t *qpol_matching_classes = NULL;
		apol_class_query_t *regex_match_query = apol_class_query_create();
		apol_class_query_set_regex(policy, regex_match_query, 1);
		apol_class_query_set_class(policy, regex_match_query, cmd_opts.class_name);
		if (apol_class_get_by_query(policy, regex_match_query, &qpol_matching_classes)) {
			apol_class_query_destroy(&regex_match_query);
			goto cleanup;
		}
		const qpol_class_t *class = NULL;
		for (size_t i = 0; i < apol_vector_get_size(qpol_matching_classes); ++i) {
			const char *class_name;
			class = apol_vector_get_element(qpol_matching_classes, i);
			if (!class)
				break;
			qpol_class_get_name(apol_policy_get_qpol(policy), class, &class_name);
			apol_vector_append(cmd_opts.class_vector, (void *)class_name);
		}
		if (!apol_vector_get_size(qpol_matching_classes)) {
			apol_vector_destroy(&qpol_matching_classes);
			apol_class_query_destroy(&regex_match_query);
			ERR(policy, "No classes match expression %s", cmd_opts.class_name);
			goto cleanup;
		}
		apol_vector_destroy(&qpol_matching_classes);
		apol_class_query_destroy(&regex_match_query);
	}

	if (!cmd_opts.semantic && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (qpol_policy_build_syn_rule_table(apol_policy_get_qpol(policy))) {
			apol_policy_destroy(&policy);
			exit(1);
		}
	}

	/* if syntactic rules are not available always do semantic search */
	if (!qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		cmd_opts.semantic = 1;
	}

	/* supress line numbers if doing semantic search or not available */
	if (cmd_opts.semantic || !qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_LINE_NUMBERS)) {
		cmd_opts.lineno = 0;
	}

	if (perform_av_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		if (!cmd_opts.semantic && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES))
			print_syn_av_results(policy, &cmd_opts, v);
		else
			print_av_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v);
	if (perform_te_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		if (!cmd_opts.semantic && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES))
			print_syn_te_results(policy, &cmd_opts, v);
		else
			print_te_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}

	apol_vector_destroy(&v);
	if (perform_ft_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		print_ft_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}

	apol_vector_destroy(&v);
	if (perform_ra_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		print_ra_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v);
	if (perform_rt_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		print_rt_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v);
	if (perform_range_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
		print_range_results(policy, &cmd_opts, v);
		fprintf(stdout, "\n");
	}
	apol_vector_destroy(&v);
	rt = 0;
      cleanup:
	apol_policy_destroy(&policy);
	apol_policy_path_destroy(&pol_path);
	free(cmd_opts.src_name);
	free(cmd_opts.tgt_name);
	free(cmd_opts.default_name);
	free(cmd_opts.class_name);
	free(cmd_opts.permlist);
	free(cmd_opts.bool_name);
	free(cmd_opts.src_role_name);
	free(cmd_opts.tgt_role_name);
	apol_vector_destroy(&cmd_opts.perm_vector);
	apol_vector_destroy(&cmd_opts.class_vector);
	exit(rt);
}
