/**
 * @file
 *
 * Implementation of permission mapping routines.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2003-2007 Tresys Technology, LLC
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

#include "policy-query-internal.h"

#include <apol/perm-map.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* use 8k line size */
#define APOL_LINE_SZ 8192

struct apol_permmap
{
	unsigned char mapped;	       /* true if this class's permissions
				        * were mapped from a file, false if
				        * using default values */
	apol_vector_t *classes;	       /* list of apol_permmap_class_t */
};

/* There is one apol_permmap_class per object class. */
typedef struct apol_permmap_class
{
	unsigned char mapped;	       /* mask */
	/** pointer to within a qpol_policy_t that represents this class */
	const qpol_class_t *c;
	/** vector of apol_permmap_perm, an element for each permission bit */
	apol_vector_t *perms;
} apol_permmap_class_t;

/**
 * Permission maps: For each object class we need to map all permisions
 * to either read and/or write, or non similar as is done for the MLS stuff.
 * This allows us to determine information flow.  These mappings will be
 * loadable so that users can re-map them as they see fit.
 */
typedef struct apol_permmap_perm
{
	/** name of permission */
	char *name;
	/** one of APOL_PERMMAP_READ, etc. */
	unsigned char map;
	/** the weight (importance) of this perm. (least) 1 - 10 (most) */
	int weight;
} apol_permmap_perm_t;

/* some perms unmapped */
#define APOL_PERMMAP_RET_UNMAPPED_PERM 0x01
/* some objects unmapped */
#define APOL_PERMMAP_RET_UNMAPPED_OBJ 0x02
/* some perms from file unknown and ignored */
#define	APOL_PERMMAP_RET_UNKNOWN_PERM 0x04
/* some object from file unknown and ignored */
#define APOL_PERMMAP_RET_UNKNOWN_OBJ 0x08
/* not enough classes/perms */
#define APOL_PERMMAP_RET_NOT_ENOUGH 0x10

/**
 * Deallocate all space used by an apol_permmap_perm_t, including the
 * pointer itself.
 *
 * @param elem Pointer to free.  If NULL then do nothing.
 */
static void permmap_perm_free(void *elem)
{
	if (elem != NULL) {
		apol_permmap_perm_t *p = (apol_permmap_perm_t *) elem;
		free(p->name);
		free(p);
	}
}

/**
 * Deallocate all space used by an apol_permmap_class_t, including the
 * pointer itself.
 *
 * @param elem Pointer to free.  If NULL then do nothing.
 */
static void permmap_class_free(void *elem)
{
	if (elem != NULL) {
		apol_permmap_class_t *c = (apol_permmap_class_t *) elem;
		apol_vector_destroy(&c->perms);
		free(c);
	}
}

/**
 * Allocate and return a new apol_permmap_perm_t.
 *
 * @param name Name of the permission.  This function will duplicate
 * the string.
 * @param map Direction of information flow.  This must be one of
 * APOL_PERMMAP_UNMAPPED, APOL_PERMMAP_READ, etc.
 * @param weight Weight of the permission.  This must be an integer
 * from APOL_PERMMAP_MIN_WEIGHT to APOL_PERMMAP_MAX_WEIGHT, inclusive.
 *
 * @return A newly allocated apol_permmap_perm_t, or NULL on out of
 * memory.  The caller is responsible for deallocating this pointer
 * via apol_permmap_perm_free().
 */
static apol_permmap_perm_t *apol_permmap_perm_create(const char *name, unsigned char map, int weight)
{
	apol_permmap_perm_t *pp;
	if ((pp = calloc(1, sizeof(*pp))) == NULL) {
		return NULL;
	}
	if ((pp->name = strdup(name)) == NULL) {
		free(pp);
		return NULL;
	}
	pp->map = map;
	pp->weight = weight;
	return pp;
}

/**
 * Allocate and return a new permission map from a policy, and
 * allocates space for defined object classes.
 *
 * @param p Policy from which to create permission map.
 *
 * @return A newly allocated map, or NULL on error.  The caller is
 * responsible for deallocating this pointer via permmap_destroy().
 */
static apol_permmap_t *apol_permmap_create_from_policy(const apol_policy_t * p)
{
	apol_permmap_t *t = NULL;
	qpol_iterator_t *class_iter = NULL, *perm_iter = NULL, *common_iter = NULL;
	size_t num_obj_classes;
	int retval = -1;

	if (p == NULL) {
		goto cleanup;
	}

	if ((t = (apol_permmap_t *) calloc(1, sizeof(*t))) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	if (qpol_policy_get_class_iter(p->p, &class_iter) < 0 || qpol_iterator_get_size(class_iter, &num_obj_classes) < 0) {
		goto cleanup;
	}
	t->mapped = 0;
	if ((t->classes = apol_vector_create_with_capacity(num_obj_classes, permmap_class_free)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(class_iter); qpol_iterator_next(class_iter)) {
		const qpol_class_t *c;
		const qpol_common_t *common;
		apol_permmap_class_t *pc = NULL;
		apol_permmap_perm_t *pp = NULL;
		size_t num_unique_perms, num_common_perms = 0;
		char *name;
		if (qpol_iterator_get_item(class_iter, (void **)&c) < 0 ||
		    qpol_class_get_perm_iter(p->p, c, &perm_iter) < 0 ||
		    qpol_iterator_get_size(perm_iter, &num_unique_perms) < 0 || qpol_class_get_common(p->p, c, &common) < 0) {
			goto cleanup;
		}
		if (common != NULL &&
		    (qpol_common_get_perm_iter(p->p, common, &common_iter) < 0 ||
		     qpol_iterator_get_size(common_iter, &num_common_perms) < 0)) {
			goto cleanup;
		}
		if ((pc = calloc(1, sizeof(*pc))) == NULL || apol_vector_append(t->classes, pc) < 0) {
			ERR(p, "%s", strerror(ENOMEM));
			permmap_class_free(pc);
			goto cleanup;
		}
		pc->mapped = 0;
		pc->c = c;
		if ((pc->perms = apol_vector_create_with_capacity(num_unique_perms + num_common_perms, permmap_perm_free)) == NULL) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
		/* initialize with all the class's unique permissions
		 * from provided policy */
		for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
			if (qpol_iterator_get_item(perm_iter, (void **)&name) < 0) {
				goto cleanup;
			}
			if ((pp = apol_permmap_perm_create(name, 0, (char)APOL_PERMMAP_MIN_WEIGHT)) == NULL ||
			    apol_vector_append(pc->perms, pp) < 0) {
				ERR(p, "%s", strerror(ENOMEM));
				permmap_perm_free(pp);
				goto cleanup;
			}
		}
		/* next initialize with common permissions */
		for (; common_iter != NULL && !qpol_iterator_end(common_iter); qpol_iterator_next(common_iter)) {
			if (qpol_iterator_get_item(common_iter, (void **)&name) < 0) {
				goto cleanup;
			}
			if ((pp = apol_permmap_perm_create(name, 0, (char)APOL_PERMMAP_MIN_WEIGHT)) == NULL ||
			    apol_vector_append(pc->perms, pp) < 0) {
				ERR(p, "%s", strerror(ENOMEM));
				permmap_perm_free(pp);
				goto cleanup;
			}
		}
		qpol_iterator_destroy(&perm_iter);
		qpol_iterator_destroy(&common_iter);
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&class_iter);
	qpol_iterator_destroy(&perm_iter);
	qpol_iterator_destroy(&common_iter);
	if (retval < 0) {
		permmap_destroy(&t);
	}
	return t;
}

void permmap_destroy(apol_permmap_t ** p)
{
	if (p == NULL || *p == NULL)
		return;
	apol_vector_destroy(&(*p)->classes);
	free(*p);
	*p = NULL;
}

/**
 * Searches through the permission map within a policy, returning the
 * record for a given object class.
 *
 * @param p Policy containing permission map.
 * @param target Target class name.
 *
 * @return Pointer to the class within the permission map, or NULL if
 * not found or on error.
 */
static apol_permmap_class_t *find_permmap_class(const apol_policy_t * p, const char *target)
{
	size_t i;
	const qpol_class_t *target_class;
	if (qpol_policy_get_class_by_name(p->p, target, &target_class) < 0) {
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(p->pmap->classes); i++) {
		apol_permmap_class_t *pc = apol_vector_get_element(p->pmap->classes, i);
		if (pc->c == target_class) {
			return pc;
		}
	}
	return NULL;
}

/**
 * Searches through the permission map's class, returning the record
 * for a given permission.
 *
 * @param p Policy to use, for error handling.
 * @param pc Permission map class to search.
 * @param target Target class name.
 *
 * @return Pointer to the permission record within the class, or NULL
 * if not found or on error.
 */
static apol_permmap_perm_t *find_permmap_perm(const apol_policy_t * p
					      __attribute__ ((unused)), const apol_permmap_class_t * pc, const char *target)
{
	size_t i;
	for (i = 0; i < apol_vector_get_size(pc->perms); i++) {
		apol_permmap_perm_t *pp = apol_vector_get_element(pc->perms, i);
		if (strcmp(pp->name, target) == 0) {
			return pp;
		}
	}
	return NULL;
}

/**
 * Given a character representation, return its numerical permission
 * map type.
 *
 * @param p Policy containing error handler.
 * @param perm_name Name of the permission.
 * @param mapid Character representing map type.
 *
 * @return One of APOL_PERMMAP_READ, etc, or APOL_PERMMAP_UNMAPPED on error.
 */
static char convert_map_char(const apol_policy_t * p, const char *perm_name, char mapid)
{
	switch (mapid) {
	case 'r':
	case 'R':
		return APOL_PERMMAP_READ;
	case 'w':
	case 'W':
		return APOL_PERMMAP_WRITE;
	case 'b':
	case 'B':
		return APOL_PERMMAP_BOTH;
	case 'n':
	case 'N':
		return APOL_PERMMAP_NONE;
	default:
		ERR(p, "Invalid map character '%c' for permission %s; permission will be unmapped.", mapid, perm_name);
		return APOL_PERMMAP_UNMAPPED;
	}
}

/**
 * Goes through a policy's permission map to check that all classes
 * had an entry within the recently read permission map file.
 *
 * @param p Policy containing permission map to check.
 *
 * @return 1 if all classes had entries, 0 if any did not.
 */
static int are_all_classes_mapped(const apol_policy_t * p)
{
	size_t i;
	for (i = 0; i < apol_vector_get_size(p->pmap->classes); i++) {
		apol_permmap_class_t *pc = apol_vector_get_element(p->pmap->classes, i);
		if (pc->mapped == 0) {
			const char *class_name;
			if (qpol_class_get_name(p->p, pc->c, &class_name) < 0) {
				return 0;
			}
			WARN(p, "Some permissions were unmapped for class %s.", class_name);
			return 0;
		}
	}
	return 1;
}

/**
 * Goes through a class's permissions to check that had an entry
 * within the recently read permission map file.
 *
 * @param p Policy containing permission map to check.
 * @param pc Class to check.
 *
 * @return 1 if all permissions had entries, 0 if any did not.
 */
static int are_all_perms_mapped(const apol_policy_t * p, const apol_permmap_class_t * pc)
{
	size_t i;
	for (i = 0; i < apol_vector_get_size(pc->perms); i++) {
		apol_permmap_perm_t *pp = apol_vector_get_element(pc->perms, i);
		if (pp->map == 0) {
			const char *class_name;
			if (qpol_class_get_name(p->p, pc->c, &class_name) < 0) {
				return 0;
			}
			WARN(p, "Permission %s was unmapped for class %s.", pp->name, class_name);
			return 0;
		}
	}
	return 1;
}

/**
 * Parse the individual permission definitions for a given class.  If
 * pc is not NULL then store them into a apol_permmap_class_t,
 * otherwise discard the read values.  If a permission was read, but
 * does not have an entry within pc, then generate a warning and
 * continue.  Finally, check that all permissions for the given class
 * have been mapped; if any have not then generate a warning.
 *
 * @param p Policy containing permission map.
 * @param fp File pointer that contains permission map data.
 * @param num_perms Number of permissions expected to be read.
 * @param pc Destination to store data; if NULL then do not store data.
 *
 * @return 0 on success, > 0 on success but with warnings, < 0 on
 * error.
 */
static int parse_permmap_class(apol_policy_t * p, FILE * fp, size_t num_perms, apol_permmap_class_t * pc)
{
	char line[APOL_LINE_SZ], perm_name[APOL_LINE_SZ], *line_ptr = NULL;
	size_t perms_read = 0;
	int retval = 0;

	while (fgets(line, sizeof(line), fp) != NULL && perms_read < num_perms) {
		char mapid;
		int perm_weight, new_weight;
		apol_permmap_perm_t *pp;

		line_ptr = line;
		apol_str_trim(line_ptr);
		if (line_ptr[0] == '#' || apol_str_is_only_white_space(line_ptr))
			continue;
		perms_read++;
		if (sscanf(line_ptr, "%s %c %d", perm_name, &mapid, &perm_weight) != 3) {
			/* This may be a perm map file w/o perm weighting. */
			if (sscanf(line_ptr, "%s %c", perm_name, &mapid) != 2) {
				ERR(p, "Permission map has an invalid line: \"%s\"", line_ptr);
				return -1;
			}
			perm_weight = APOL_PERMMAP_MAX_WEIGHT;
		}
		if (strcmp(perm_name, "class") == 0) {
			ERR(p, "There were supposed to be %zu permissions, but only %zu were found.", num_perms, perms_read);
			return -1;
		}
		new_weight = perm_weight;
		if (perm_weight > APOL_PERMMAP_MAX_WEIGHT) {
			new_weight = APOL_PERMMAP_MAX_WEIGHT;
		} else if (perm_weight < APOL_PERMMAP_MIN_WEIGHT) {
			new_weight = APOL_PERMMAP_MIN_WEIGHT;
		}
		if (new_weight != perm_weight) {
			WARN(p, "Permission %s's weight %d is invalid.  Setting it to %d instead.", perm_name, perm_weight,
			     new_weight);
			perm_weight = new_weight;
		}
		if (pc != NULL) {
			if ((pp = find_permmap_perm(p, pc, perm_name)) == NULL) {
				WARN(p,
				     "Permission %s was defined in the permission map file but not within the policy.  It will be ignored.",
				     perm_name);
				retval |= APOL_PERMMAP_RET_UNKNOWN_PERM;
			} else {
				pp->weight = perm_weight;
				pp->map = convert_map_char(p, perm_name, mapid);
			}
		}
	}
	if (perms_read != num_perms) {
		WARN(p, "There were supposed to be %zu permissions, but only %zu were found.", num_perms, perms_read);
		retval |= APOL_PERMMAP_RET_NOT_ENOUGH;
	}
	if (pc != NULL && !are_all_perms_mapped(p, pc)) {
		retval |= APOL_PERMMAP_RET_UNMAPPED_PERM;
	}
	return retval;
}

/**
 * Parse the permission map found within a file pointer, storing the
 * information into the map within a policy.  If there is a non-fatal
 * error while loading (e.g., file declared an object class that does
 * not exist within the policy) then generate a warning string and
 * send it to the error handler stored within the policy.
 *
 * @param p Policy containing a newly allocated permission map.
 * @param fp File pointer that contains permission map data.
 *
 * @return 0 on success, > 0 on success but with warnings, < 0 on
 * error.
 */
static int parse_permmap(apol_policy_t * p, FILE * fp)
{
	char line[APOL_LINE_SZ], class_name[APOL_LINE_SZ], *line_ptr = NULL;
	size_t num_classes = 0, num_perms = 0;
	size_t i;
	int retval = 0;

	/* first read number of classes */
	while (fgets(line, sizeof(line), fp) != NULL) {
		line_ptr = line;;
		apol_str_trim(line_ptr);
		if (line_ptr[0] != '#' && (sscanf(line_ptr, "%zu", &num_classes) == 1)) {
			break;
		}
	}
	if (num_classes == 0) {
		ERR(p, "%s", "No object classes were defined in the permission map file.");
		return -1;
	}

	/* next read each class */
	for (i = 0; i < num_classes; i++) {
		apol_permmap_class_t *pc;
		int found_class_decl = 0, rt;
		while (fgets(line, APOL_LINE_SZ, fp) != NULL) {
			line_ptr = line;
			apol_str_trim(line_ptr);
			if (line_ptr[0] != '#' && (sscanf(line_ptr, "%*s %s %zu", class_name, &num_perms) == 2)) {
				found_class_decl = 1;
				break;
			}
		}
		if (!found_class_decl) {
			WARN(p, "Permission map file was supposed to have %zu classes, but only %zu were found.", num_classes, i);
			return APOL_PERMMAP_RET_NOT_ENOUGH;
		}
		if ((pc = find_permmap_class(p, class_name)) == NULL) {
			WARN(p,
			     "Object class %s was defined in the permission map file but not within the policy.  It will be ignored.",
			     class_name);
			/* skip to next record */
			parse_permmap_class(p, fp, num_perms, NULL);
			retval |= APOL_PERMMAP_RET_UNKNOWN_OBJ;
		} else {
			if ((rt = parse_permmap_class(p, fp, num_perms, pc)) < 0) {
				return -1;
			}
			pc->mapped = 1;
			retval |= rt;
		}
	}
	return retval;
}

int apol_policy_open_permmap(apol_policy_t * p, const char *filename)
{
	FILE *outfile = NULL;
	int retval = -1, rt = 0;

	if (p == NULL || filename == NULL) {
		goto cleanup;
	}
	permmap_destroy(&p->pmap);
	if ((p->pmap = apol_permmap_create_from_policy(p)) == NULL) {
		goto cleanup;
	}

	if ((outfile = fopen(filename, "r")) == NULL) {
		ERR(p, "Could not open permission map %s for reading: %s", filename, strerror(errno));
		goto cleanup;
	}

	if ((rt = parse_permmap(p, outfile)) < 0) {
		goto cleanup;
	}

	/* check that all classes have been mapped */
	if (rt == 0 && !are_all_classes_mapped(p)) {
		rt = APOL_PERMMAP_RET_UNMAPPED_OBJ;
	}
	p->pmap->mapped = 1;

	retval = rt;
      cleanup:
	if (outfile != NULL) {
		fclose(outfile);
	}
	return retval;
}

int apol_permmap_load(apol_policy_t * p, const char *filename)
{
	return apol_policy_open_permmap(p, filename);
}

int apol_policy_save_permmap(const apol_policy_t * p, const char *filename)
{
	time_t ltime;
	size_t i, j;
	FILE *outfile = NULL;
	int retval = -1;

	if (p == NULL || p->pmap == NULL || filename == NULL)
		goto cleanup;

	if ((outfile = fopen(filename, "w")) == NULL) {
		ERR(p, "Could not open permission map %s for writing: %s", filename, strerror(errno));
		goto cleanup;
	}

	if (time(&ltime) == (time_t) - 1) {
		ERR(p, "Could not get time: %s", strerror(errno));
		goto cleanup;
	}
	if (fprintf(outfile, "# Auto-generated by apol on %s\n", ctime(&ltime)) < 0 ||
	    fprintf(outfile, "#\n# permission map file\n\n\n") < 0 ||
	    fprintf(outfile, "Number of classes (mapped?: %s):\n", (p->pmap->mapped ? "yes" : "no")) < 0 ||
	    fprintf(outfile, "%zu\n", apol_vector_get_size(p->pmap->classes)) < 0) {
		ERR(p, "Write error: %s", strerror(errno));
		goto cleanup;
	}

	for (i = 0; i < apol_vector_get_size(p->pmap->classes); i++) {
		apol_permmap_class_t *pc = apol_vector_get_element(p->pmap->classes, i);
		const char *class_name;
		if (qpol_class_get_name(p->p, pc->c, &class_name) < 0) {
			goto cleanup;
		}
		if (fprintf(outfile, "\nclass %s %zu\n", class_name, apol_vector_get_size(pc->perms)) < 0) {
			ERR(p, "Write error: %s", strerror(errno));
			goto cleanup;
		}

		for (j = 0; j < apol_vector_get_size(pc->perms); j++) {
			apol_permmap_perm_t *pp = apol_vector_get_element(pc->perms, j);
			char *s;
			if (fprintf(outfile, "%s%18s	 ", pp->map & APOL_PERMMAP_UNMAPPED ? "#" : "", pp->name) < 0) {
				ERR(p, "Write error: %s", strerror(errno));
				goto cleanup;
			}
			switch (pp->map) {
			case APOL_PERMMAP_READ:
				s = "r";
				break;
			case APOL_PERMMAP_WRITE:
				s = "w";
				break;
			case APOL_PERMMAP_BOTH:
				s = "b";
				break;
			case APOL_PERMMAP_NONE:
				s = "n";
				break;
			case APOL_PERMMAP_UNMAPPED:
				s = "u";
				break;
			default:
				s = "?";
			}
			if (fprintf(outfile, "%s  %10d\n", s, pp->weight) < 0) {
				ERR(p, "Write error: %s", strerror(errno));
				goto cleanup;
			}
		}
	}

	retval = 0;
      cleanup:
	if (outfile != NULL) {
		fclose(outfile);
	}
	return retval;
}

int apol_permmap_save(apol_policy_t * p, const char *filename)
{
	return apol_policy_save_permmap(p, filename);
}

int apol_policy_get_permmap(const apol_policy_t * p, const char *class_name, const char *perm_name, int *map, int *weight)
{
	apol_permmap_class_t *pc;
	apol_permmap_perm_t *pp;
	if (p == NULL || p->pmap == NULL) {
		return -1;
	}
	if ((pc = find_permmap_class(p, class_name)) == NULL || (pp = find_permmap_perm(p, pc, perm_name)) == NULL) {
		ERR(p, "Could not find permission %s in class %s.", perm_name, class_name);
		return -1;
	}
	*map = pp->map;
	*weight = pp->weight;
	return 0;
}

int apol_permmap_get(apol_policy_t * p, const char *class_name, const char *perm_name, int *map, int *weight)
{
	return apol_policy_get_permmap(p, class_name, perm_name, map, weight);
}

int apol_policy_set_permmap(apol_policy_t * p, const char *class_name, const char *perm_name, int map, int weight)
{
	apol_permmap_class_t *pc;
	apol_permmap_perm_t *pp;
	if (p == NULL || p->pmap == NULL) {
		return -1;
	}
	if ((pc = find_permmap_class(p, class_name)) == NULL || (pp = find_permmap_perm(p, pc, perm_name)) == NULL) {
		ERR(p, "Could not find permission %s in class %s.", perm_name, class_name);
		return -1;
	}
	pp->map = map;
	if (weight > APOL_PERMMAP_MAX_WEIGHT) {
		weight = APOL_PERMMAP_MAX_WEIGHT;
	} else if (weight < APOL_PERMMAP_MIN_WEIGHT) {
		weight = APOL_PERMMAP_MIN_WEIGHT;
	}
	pp->weight = weight;
	return 0;
}

int apol_permmap_set(apol_policy_t * p, const char *class_name, const char *perm_name, int map, int weight)
{
	return apol_policy_set_permmap(p, class_name, perm_name, map, weight);
}
