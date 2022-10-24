#ifndef HANDLE_H_
#define HANDLE_H_
#include <stdint.h>
#include "binder.h"

bool publish_handle(struct binder_state *bs, uint64_t handle, const char *srv_name);
uint64_t grab_handle(struct binder_state *bs, const char *srv_name);


#endif /*! HANDLE_H_ */
