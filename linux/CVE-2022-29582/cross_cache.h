#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "err_state.h"

enum {
    PHASE_0,
    PHASE_1,
    PHASE_2,
    PHASE_3,
    PHASE_4,
    PHASE_CLEAN
};

struct cross_cache {
    uint32_t objs_per_page;
    uint32_t cpu_partial;
    uint32_t objs_per_slab;
    int64_t *object_refs;
    uint32_t n_objects;
    uint8_t phase;
    uint32_t prev_count;
    int (*allocate)();
    int (*free)(int64_t);
};

struct cross_cache* init_cross_cache(void *allocate_fptr,
                                     void *free_fptr,
                                     uint32_t objs_per_slab,
                                     uint32_t cpu_partial,
                                     uint32_t objs_per_page);
void deinit_cross_cache(struct cross_cache* cc);
int64_t cc_next(struct cross_cache *cc);


