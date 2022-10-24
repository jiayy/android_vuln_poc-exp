#ifndef __BINDER_LOOKUP_H

#define __BINDER_LOOKUP_H

int publish_handle(struct binder_state *bs, uint64_t handle, char *name);
uint32_t grab_handle(struct binder_state *bs, char *name);
uint32_t grab_handle_and_buffer(struct binder_state *bs, char *name, uint64_t *buffer_end);
void cleanup_lookup(struct binder_state *bs);
int lookup_service(struct binder_state *bs, char *name);

#endif
